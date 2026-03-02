import * as http from 'http';
import type { ProxyConfig, ProxyUpstream, ARPEvent } from '../types';
import type { EventEngine } from '../engine/event-engine';
import type { PromptInterceptor } from '../interceptors/prompt';
import type { MCPProtocolInterceptor } from '../interceptors/mcp-protocol';
import type { A2AProtocolInterceptor } from '../interceptors/a2a-protocol';
import { bufferBody, forwardRequest, sendResponse, sendError } from './forward';
import { hasFeature, PREMIUM_FEATURES } from '../license';

export interface ARPProxyDeps {
  engine: EventEngine;
  promptInterceptor?: PromptInterceptor;
  mcpInterceptor?: MCPProtocolInterceptor;
  a2aInterceptor?: A2AProtocolInterceptor;
}

/**
 * ARP HTTP Reverse Proxy — sits between clients and upstream AI services,
 * inspecting requests and responses for AI-layer threats.
 *
 * Zero external dependencies (uses Node.js built-in http module).
 * Alert-only by default; optional blockOnDetection mode.
 */
export class ARPProxy {
  private readonly config: ProxyConfig;
  private readonly deps: ARPProxyDeps;
  private server: http.Server | null = null;

  constructor(config: ProxyConfig, deps: ARPProxyDeps) {
    this.config = config;
    this.deps = deps;
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res).catch((err) => {
          const message = err instanceof Error ? err.message : String(err);
          const statusCode = message === 'Request body too large' ? 413 : 502;
          const clientMessage = message === 'Request body too large'
            ? 'Request body too large'
            : 'Bad gateway';
          sendError(res, statusCode, clientMessage);
        });
      });

      this.server.listen(this.config.port, () => {
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  getPort(): number {
    return this.config.port;
  }

  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const url = req.url ?? '/';

    // Find matching upstream
    const upstream = this.findUpstream(url);
    if (!upstream) {
      sendError(res, 404, 'Not found');
      return;
    }

    // Buffer the request body
    const body = await bufferBody(req);
    const bodyStr = body.length > 0 ? body.toString('utf-8') : '';

    // Pre-flight inspection (scan request)
    const blocked = await this.inspectRequest(upstream, bodyStr, url);
    if (blocked && this.config.blockOnDetection) {
      // Blocking mode is a premium feature
      const canBlock = await hasFeature(PREMIUM_FEATURES.BLOCKING_MODE);
      if (canBlock) {
        sendError(res, 403, 'Request blocked by ARP: threat detected');
        return;
      }
      // Community edition: alert only, request passes through
    }

    // Strip the pathPrefix from the URL before forwarding
    let forwardPath = url.startsWith(upstream.pathPrefix)
      ? url.slice(upstream.pathPrefix.length) || '/'
      : url;

    // Validate forward path is relative (prevent SSRF via absolute URL in path)
    if (!forwardPath.startsWith('/')) {
      forwardPath = '/' + forwardPath;
    }
    if (/^\/\/|^\/[a-zA-Z]+:/.test(forwardPath)) {
      sendError(res, 400, 'Bad request');
      return;
    }

    // Forward to upstream
    const result = await forwardRequest(upstream.target, req, body, forwardPath);

    // Post-flight inspection (scan response)
    const responseStr = result.body.toString('utf-8');
    await this.inspectResponse(upstream, responseStr);

    // Send response back to client
    sendResponse(res, result.response.statusCode ?? 200, result.response.headers, result.body);
  }

  private findUpstream(url: string): ProxyUpstream | undefined {
    // Sort by prefix length (longest match first)
    const sorted = [...this.config.upstreams].sort(
      (a, b) => b.pathPrefix.length - a.pathPrefix.length,
    );
    return sorted.find((u) => url.startsWith(u.pathPrefix));
  }

  /**
   * Inspect inbound request based on upstream protocol type.
   * Returns true if a threat was detected.
   */
  private async inspectRequest(
    upstream: ProxyUpstream,
    bodyStr: string,
    _url: string,
  ): Promise<boolean> {
    if (!bodyStr) return false;

    let detected = false;

    switch (upstream.protocol) {
      case 'openai-api': {
        detected = this.inspectOpenAIRequest(bodyStr);
        break;
      }
      case 'mcp-http': {
        detected = this.inspectMCPRequest(bodyStr);
        break;
      }
      case 'a2a': {
        detected = this.inspectA2ARequest(bodyStr);
        break;
      }
      case 'passthrough':
      default:
        break;
    }

    return detected;
  }

  /**
   * Inspect outbound response based on upstream protocol type.
   */
  private async inspectResponse(
    upstream: ProxyUpstream,
    bodyStr: string,
  ): Promise<boolean> {
    if (!bodyStr) return false;

    let detected = false;

    switch (upstream.protocol) {
      case 'openai-api': {
        detected = this.inspectOpenAIResponse(bodyStr);
        break;
      }
      case 'mcp-http': {
        detected = this.inspectMCPResponse(bodyStr);
        break;
      }
      case 'a2a': {
        detected = this.inspectA2AResponse(bodyStr);
        break;
      }
      case 'passthrough':
      default:
        break;
    }

    return detected;
  }

  // --- Protocol-specific inspectors ---

  private inspectOpenAIRequest(bodyStr: string): boolean {
    if (!this.deps.promptInterceptor) return false;

    try {
      const parsed = JSON.parse(bodyStr);
      const messages = parsed.messages;
      if (!Array.isArray(messages)) return false;

      let detected = false;
      for (const msg of messages) {
        if (msg.role === 'user' && typeof msg.content === 'string') {
          const result = this.deps.promptInterceptor.scanInput(msg.content);
          if (result.detected) detected = true;
        }
      }
      return detected;
    } catch {
      return false;
    }
  }

  private inspectOpenAIResponse(bodyStr: string): boolean {
    if (!this.deps.promptInterceptor) return false;

    try {
      const parsed = JSON.parse(bodyStr);
      const choices = parsed.choices;
      if (!Array.isArray(choices)) return false;

      let detected = false;
      for (const choice of choices) {
        const content = choice.message?.content;
        if (typeof content === 'string') {
          const result = this.deps.promptInterceptor.scanOutput(content);
          if (result.detected) detected = true;
        }
      }
      return detected;
    } catch {
      return false;
    }
  }

  private inspectMCPRequest(bodyStr: string): boolean {
    if (!this.deps.mcpInterceptor) return false;

    try {
      const parsed = JSON.parse(bodyStr);

      // JSON-RPC format: { method: "tools/call", params: { name: "...", arguments: {...} } }
      if (parsed.method === 'tools/call' && parsed.params) {
        const toolName = parsed.params.name;
        const args = parsed.params.arguments ?? {};
        if (typeof toolName === 'string') {
          const result = this.deps.mcpInterceptor.scanToolCall(toolName, args);
          return result.detected;
        }
      }

      return false;
    } catch {
      return false;
    }
  }

  private inspectMCPResponse(bodyStr: string): boolean {
    if (!this.deps.promptInterceptor) return false;

    try {
      const parsed = JSON.parse(bodyStr);

      // JSON-RPC result: { result: { content: [{ type: "text", text: "..." }] } }
      if (parsed.result?.content && Array.isArray(parsed.result.content)) {
        let detected = false;
        for (const part of parsed.result.content) {
          if (part.type === 'text' && typeof part.text === 'string') {
            const result = this.deps.promptInterceptor.scanOutput(part.text);
            if (result.detected) detected = true;
          }
        }
        return detected;
      }

      // JSON-RPC error: { error: { message: "..." } }
      if (parsed.error?.message && typeof parsed.error.message === 'string') {
        const result = this.deps.promptInterceptor.scanOutput(parsed.error.message);
        return result.detected;
      }

      return false;
    } catch {
      return false;
    }
  }

  private inspectA2AResponse(bodyStr: string): boolean {
    if (!this.deps.promptInterceptor) return false;

    try {
      const parsed = JSON.parse(bodyStr);

      // A2A response: { content: "..." } or { message: "..." }
      const content = parsed.content ?? parsed.message ?? '';
      if (typeof content === 'string' && content) {
        const result = this.deps.promptInterceptor.scanOutput(content);
        return result.detected;
      }

      return false;
    } catch {
      return false;
    }
  }

  private inspectA2ARequest(bodyStr: string): boolean {
    if (!this.deps.a2aInterceptor) return false;

    try {
      const parsed = JSON.parse(bodyStr);

      // A2A JSON-RPC: { method: "tasks/send", params: { ... } }
      // Or direct message format: { from: "...", to: "...", content: "..." }
      const from = parsed.from ?? parsed.params?.from ?? 'unknown';
      const to = parsed.to ?? parsed.params?.to ?? 'unknown';

      // Extract content from various A2A message formats
      let content = '';
      if (typeof parsed.content === 'string') {
        content = parsed.content;
      } else if (parsed.params?.message?.parts) {
        // A2A protocol message parts
        for (const part of parsed.params.message.parts) {
          if (part.type === 'text' && typeof part.text === 'string') {
            content += part.text + '\n';
          }
        }
      } else if (typeof parsed.params?.content === 'string') {
        content = parsed.params.content;
      }

      if (content) {
        const result = this.deps.a2aInterceptor.scanMessage(from, to, content);
        return result.detected;
      }

      return false;
    } catch {
      return false;
    }
  }
}
