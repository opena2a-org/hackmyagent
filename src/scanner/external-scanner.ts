/**
 * External Scanner
 * Scans remote targets for exposed MCP endpoints, configs, and credentials
 */

import * as net from 'net';
import * as http from 'http';
import * as https from 'https';
import type { ExternalScanResult, ExternalFinding, ScannerOptions, FindingSeverity, PortState } from './types';

// Default ports to scan
export const DEFAULT_PORTS = [80, 443];

// The longest chain of sequential HTTP probes one port receives (CONFIG_PATHS);
// the other categories run beside it, so this bounds the probe phase.
const MAX_PROBE_CHAIN = 6;

// Config file paths to check
const CONFIG_PATHS = [
  '/.claude/settings.json',
  '/mcp.json',
  '/.cursor/mcp.json',
  '/.vscode/mcp.json',
  '/config.json',
  '/.env',
];

// MCP endpoint paths to check
const MCP_SSE_PATHS = ['/sse', '/events', '/mcp/sse', '/mcp/events'];
const MCP_TOOLS_PATHS = ['/tools', '/list', '/mcp/tools', '/mcp/list'];

// CLAUDE.md paths
const CLAUDE_MD_PATHS = ['/CLAUDE.md', '/.claude/CLAUDE.md'];

// API key patterns
const API_KEY_PATTERNS = [
  { name: 'Anthropic', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{6,}/ },
  { name: 'OpenAI', pattern: /sk-proj-[a-zA-Z0-9]{6,}/ },
  { name: 'OpenAI', pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: 'AWS', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
];

// Severity weights for scoring
const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 10,
  low: 5,
};

function generateId(): string {
  return Math.random().toString(36).substring(2, 10);
}

function calculateGrade(score: number): string {
  if (score >= 90) return 'strong';
  if (score >= 80) return 'good';
  if (score >= 70) return 'moderate';
  if (score >= 60) return 'improving';
  return 'needs-attention';
}

function isPrivateOrReserved(hostname: string): boolean {
  if (hostname === '169.254.169.254' || hostname === 'metadata.google.internal') return true;
  if (net.isIPv4(hostname)) {
    const parts = hostname.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 0) return true;
  }
  return false;
}

function validateTarget(target: string): void {
  // Validate protocol if a full URL was provided
  if (target.includes('://')) {
    const protocol = target.split('://')[0].toLowerCase();
    if (protocol !== 'http' && protocol !== 'https') {
      throw new Error(`Unsupported protocol "${protocol}". Only http and https are allowed.`);
    }
  }
}

export interface ParsedTarget {
  /** The name handed to DNS and to `socket.connect` -- never the raw URL. */
  hostname: string;
  /** The port the URL named, when it named one; `-p` still overrides it. */
  urlPort?: number;
  /** The scheme the URL named; a bare host has none. */
  scheme?: 'http' | 'https';
}

/**
 * Split the target the user typed into what the network layer needs.
 *
 * 0.33.0 handed the raw string to `socket.connect`, so `scan https://host`
 * asked DNS for the name "https://host", failed on every port inside the
 * millisecond and reported a live site as unreachable (advertised-command
 * audit 2026-09-13). A URL is parsed; a bare `host` or `host:port` is split.
 */
export function parseTarget(target: string): ParsedTarget {
  validateTarget(target);
  if (target.includes('://')) {
    let url: URL;
    try {
      url = new URL(target);
    } catch {
      throw new Error(`Cannot parse "${target}" as a URL. Give a hostname, an IP address, or an http(s) URL.`);
    }
    return {
      hostname: url.hostname.replace(/^\[|\]$/g, ''),
      urlPort: url.port ? parseInt(url.port, 10) : undefined,
      scheme: url.protocol === 'https:' ? 'https' : 'http',
    };
  }
  if (net.isIPv6(target)) return { hostname: target };
  // A schemeless `host/path` scans the host, as 0.33.0 did; the path is not
  // part of what a port scan can use.
  const hostOnly = target.split(/[/?#]/)[0];
  const hostPort = hostOnly.match(/^\[?([^\]/]+?)\]?(?::(\d{1,5}))?$/);
  if (!hostPort) {
    throw new Error(`Cannot parse "${target}" as a target. Give a hostname, an IP address, or an http(s) URL.`);
  }
  return {
    hostname: hostPort[1],
    urlPort: hostPort[2] ? parseInt(hostPort[2], 10) : undefined,
  };
}

/** The ports a scan will probe for this target and `-p` value. */
export function resolvePorts(target: string, customPorts?: number[]): number[] {
  if (customPorts && customPorts.length > 0) return customPorts;
  const { urlPort } = parseTarget(target);
  return urlPort ? [urlPort] : DEFAULT_PORTS;
}

// Ports a host is asked on when every scanned port stayed silent, so that
// "filtered" and "offline" are not the same answer. A refusal counts as an
// answer: the host is there, the port is not.
const REACHABILITY_PORTS = [443, 80];

function looksLikeHtml(body: string): boolean {
  return /^\s*<(?:!doctype|html|head|body)\b/i.test(body);
}

/**
 * An MCP tools listing is JSON with a `tools` member. 0.33.0 accepted any 200
 * whose body contained the word "tools", so a site with an HTML /tools page
 * was reported as exposing an MCP tools endpoint (measured on opena2a.org
 * once the probes stopped stalling; a CRITICAL on a marketing page).
 */
function looksLikeToolsListing(result: { contentType?: string; body?: string }): boolean {
  const body = result.body?.trim();
  if (!body) return false;
  const isJson = result.contentType?.includes('application/json') || body.startsWith('{') || body.startsWith('[');
  if (!isJson || looksLikeHtml(body)) return false;
  try {
    const parsed = JSON.parse(body);
    if (Array.isArray(parsed)) return parsed.some((t) => t && typeof t === 'object' && 'name' in t);
    return !!parsed && typeof parsed === 'object' && ('tools' in parsed || (parsed.result && typeof parsed.result === 'object' && 'tools' in parsed.result));
  } catch {
    // A truncated listing (the body is capped at 10 KB) still names the key.
    return /"tools"\s*:/.test(body);
  }
}

function describeStates(states: Record<number, PortState>): string {
  return Object.entries(states).map(([port, state]) => `${port} ${state}`).join(', ');
}

export class ExternalScanner {
  async scan(target: string, options?: ScannerOptions): Promise<ExternalScanResult> {
    // Validate protocol (block file://, gopher://, etc.) and split the target.
    const parsed = parseTarget(target);
    const { hostname } = parsed;
    if (isPrivateOrReserved(hostname)) {
      // Log warning but allow -- scanning local services is a core use case for security testing
      console.warn(`[HMA] Warning: scanning private/reserved address "${hostname}". Ensure you have authorization.`);
    }

    const startTime = Date.now();
    const timeout = options?.timeout ?? 2000;
    const ports = resolvePorts(target, options?.ports);
    const skipPortScan = options?.skipPortScan ?? false;

    // Global scan budget. Every phase below is bounded by `timeout` and runs
    // its members concurrently: the port probes (one round), the reachability
    // re-check (one round), and the HTTP probes (at most MAX_PROBE_CHAIN
    // sequential requests per port, categories side by side). 0.33.0 budgeted
    // ports x timeout and then ran 17 sequential probes per open port against
    // it, so a host that answered on both default ports "timed out".
    const globalTimeout = Math.min(timeout * (MAX_PROBE_CHAIN + 4), 60_000);

    // Race the scan against a global timeout
    const scanWork = async (): Promise<ExternalScanResult> => {
      // Port scan
      let openPorts: number[] = [];
      let portStates: Record<number, PortState> | undefined;
      let hostReachable: boolean | undefined;
      let unreachableReason: 'unresolved' | 'silent' | undefined;
      if (!skipPortScan) {
        portStates = await this.scanPorts(hostname, ports, timeout);
        openPorts = ports.filter((p) => portStates![p] === 'open').sort((a, b) => a - b);
        const states = Object.values(portStates);
        if (states.includes('open') || states.includes('closed')) {
          hostReachable = true;
        } else if (states.includes('unresolved')) {
          hostReachable = false;
          unreachableReason = 'unresolved';
        } else {
          // Everything scanned stayed silent. Ask the two ports a public host
          // most often answers on before calling it offline.
          const extra = REACHABILITY_PORTS.filter((p) => !ports.includes(p));
          const answered = extra.length > 0
            ? Object.values(await this.scanPorts(hostname, extra, timeout)).some((s) => s === 'open' || s === 'closed')
            : false;
          hostReachable = answered;
          if (!answered) unreachableReason = 'silent';
        }
      }

      // Run security checks on open ports, ports side by side
      const insecure = options?.insecure === true;
      const perPort = await Promise.all(
        openPorts.map((port) => this.checkPort(hostname, port, timeout, insecure, parsed.scheme))
      );
      const findings: ExternalFinding[] = perPort.flat();

      // If no port was open, nothing was tested and the score is not applicable.
      // Say WHICH of the three states the host is in: it never answered, its
      // name never resolved, or it answered without an open port among those
      // scanned. 0.33.0 folded all three into "Target unreachable".
      if (openPorts.length === 0 && !skipPortScan) {
        const duration = Date.now() - startTime;
        const scanned = ports.join(', ');
        const finding: ExternalFinding = hostReachable
          ? {
              id: generateId(),
              checkId: 'SCAN-NO-OPEN-PORTS',
              severity: 'low' as FindingSeverity,
              title: 'Target reachable, no open ports among those scanned',
              description: `${hostname} answered, but none of ports ${scanned} accepted a connection. Nothing was tested on it, so the score is not applicable.`,
              port: 0,
              evidence: `Port states: ${describeStates(portStates!)}`,
              impact: 'No exposure was measured on the scanned ports; a service on another port is untested',
              fix: 'Scan the ports the service listens on, e.g. -p 3000,8080.',
            }
          : unreachableReason === 'unresolved'
            ? {
                id: generateId(),
                checkId: 'SCAN-UNREACHABLE',
                severity: 'medium' as FindingSeverity,
                title: 'Target unreachable',
                description: `${hostname} did not resolve. Score is not applicable — nothing was tested.`,
                port: 0,
                evidence: `DNS lookup failed for ${hostname}`,
                impact: 'Cannot assess security posture of an unreachable target',
                fix: 'Check the spelling of the hostname, or scan the IP address directly.',
              }
            : {
                id: generateId(),
                checkId: 'SCAN-UNREACHABLE',
                severity: 'medium' as FindingSeverity,
                title: 'Target unreachable',
                description: `Nothing answered on ports ${scanned} of ${hostname} within ${timeout}ms each${REACHABILITY_PORTS.some((p) => !ports.includes(p)) ? ', nor on 443 or 80' : ''}. The host may be offline or filtering connections. Score is not applicable — nothing was tested.`,
                port: 0,
                evidence: `Port states: ${describeStates(portStates!)}`,
                impact: 'Cannot assess security posture of an unreachable target',
                fix: 'Verify the host is running and accessible from this network. Try -p with the ports the service listens on, or a longer -t timeout.',
              };
        return {
          id: generateId(),
          target,
          score: -1,
          grade: 'N/A',
          findings: [finding],
          duration,
          timestamp: new Date(),
          openPorts: [],
          hostReachable,
          portStates,
        };
      }

      // Calculate score using exponential decay (diminishing returns per finding)
      let weightedSum = 0;
      for (const finding of findings) {
        weightedSum += SEVERITY_WEIGHTS[finding.severity];
      }
      const DECAY_CONSTANT = 150;
      const score = weightedSum === 0
        ? 100
        : Math.round(100 * Math.exp(-weightedSum / DECAY_CONSTANT));

      const grade = calculateGrade(score);
      const duration = Date.now() - startTime;

      return {
        id: generateId(),
        target,
        score,
        grade,
        findings,
        duration,
        timestamp: new Date(),
        openPorts,
        ...(hostReachable === undefined ? {} : { hostReachable }),
        ...(portStates === undefined ? {} : { portStates }),
      };
    };

    let timer: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Scan timed out after ${globalTimeout}ms (${ports.length} ports, ${timeout}ms per connection). Try fewer ports (-p 80,443) or a longer -t timeout.`)), globalTimeout);
    });

    try {
      return await Promise.race([scanWork(), timeoutPromise]);
    } finally {
      // The timer must not keep the process alive after the scan has answered.
      if (timer) clearTimeout(timer);
    }
  }

  private async scanPorts(
    host: string,
    ports: number[],
    timeout: number
  ): Promise<Record<number, PortState>> {
    const states: Record<number, PortState> = {};
    await Promise.all(
      ports.map(async (port) => {
        states[port] = await this.probePort(host, port, timeout);
      })
    );
    return states;
  }

  /**
   * One TCP connect, and WHY it ended. 0.33.0 collapsed timeout, refusal and
   * a failed DNS lookup into `false`, which is how a name that never resolved
   * and a host that never answered read the same as a closed port.
   */
  private probePort(host: string, port: number, timeout: number): Promise<PortState> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let settled = false;
      const finish = (state: PortState) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(state);
      };

      socket.setTimeout(timeout);
      socket.on('connect', () => finish('open'));
      socket.on('timeout', () => finish('filtered'));
      socket.on('error', (err: NodeJS.ErrnoException) => {
        switch (err.code) {
          case 'ENOTFOUND':
          case 'EAI_AGAIN':
          case 'EAI_NONAME':
          case 'EAI_FAIL':
            return finish('unresolved');
          case 'ECONNREFUSED':
          case 'ECONNRESET':
            return finish('closed');
          case 'ETIMEDOUT':
            return finish('filtered');
          default:
            return finish('error');
        }
      });

      socket.connect(port, host);
    });
  }

  private async checkPort(
    hostname: string,
    port: number,
    timeout: number,
    insecure = false,
    scheme?: 'http' | 'https'
  ): Promise<ExternalFinding[]> {
    // 443 is TLS; a URL target that named its scheme and port is believed.
    const useHttps = port === 443 || (scheme === 'https' && port !== 80);
    const host = net.isIPv6(hostname) ? `[${hostname}]` : hostname;
    const baseUrl = `http${useHttps ? 's' : ''}://${host}:${port}`;

    // The five probe categories run side by side; each is a short sequential
    // chain (the longest is CONFIG_PATHS, MAX_PROBE_CHAIN). 0.33.0 ran all
    // seventeen requests one after another, which is what outran the budget.
    const [sse, tools, configs, claudeMd, apiKeys] = await Promise.all([
      this.probeMcpSse(baseUrl, port, timeout, insecure),
      this.probeMcpTools(baseUrl, port, timeout, insecure),
      this.probeConfigFiles(baseUrl, port, timeout, insecure),
      this.probeClaudeMd(baseUrl, port, timeout, insecure),
      this.probeRootForApiKeys(baseUrl, port, timeout, insecure),
    ]);
    return [...sse, ...tools, ...configs, ...claudeMd, ...apiKeys];
  }

  private async probeMcpSse(baseUrl: string, port: number, timeout: number, insecure: boolean): Promise<ExternalFinding[]> {
    for (const path of MCP_SSE_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.contentType?.includes('text/event-stream')) {
        return [{
          id: generateId(),
          checkId: 'MCP-SSE',
          severity: 'critical',
          title: 'MCP SSE Endpoint Exposed',
          description: 'Server-Sent Events endpoint for MCP is publicly accessible',
          port,
          path,
          evidence: `Content-Type: ${result.contentType}`,
          impact: 'Attackers can connect to the MCP server and potentially execute commands',
          fix: 'Restrict access with authentication or firewall rules',
        }];
      }
    }
    return [];
  }

  private async probeMcpTools(baseUrl: string, port: number, timeout: number, insecure: boolean): Promise<ExternalFinding[]> {
    for (const path of MCP_TOOLS_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.status === 200 && looksLikeToolsListing(result)) {
        return [{
          id: generateId(),
          checkId: 'MCP-TOOLS',
          severity: 'critical',
          title: 'MCP Tools Endpoint Exposed',
          description: 'MCP tools listing is publicly accessible',
          port,
          path,
          evidence: `Found tools listing at ${path}`,
          impact: 'Attackers can enumerate available MCP tools and capabilities',
          fix: 'Restrict access with authentication or remove from public access',
        }];
      }
    }
    return [];
  }

  private async probeConfigFiles(baseUrl: string, port: number, timeout: number, insecure: boolean): Promise<ExternalFinding[]> {
    const findings: ExternalFinding[] = [];
    for (const path of CONFIG_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.status === 200 && result.body) {
        // Check if it looks like JSON config
        if (
          result.contentType?.includes('application/json') ||
          result.body.trim().startsWith('{')
        ) {
          findings.push({
            id: generateId(),
            checkId: 'CONFIG-EXPOSED',
            severity: 'critical',
            title: 'Configuration File Exposed',
            description: `Configuration file ${path} is publicly accessible`,
            port,
            path,
            evidence: `HTTP 200 at ${path}`,
            impact: 'Configuration files may contain sensitive settings, API keys, or server details',
            fix: 'Remove file from public access or configure web server to deny access',
          });
        }
      }
    }
    return findings;
  }

  private async probeClaudeMd(baseUrl: string, port: number, timeout: number, insecure: boolean): Promise<ExternalFinding[]> {
    for (const path of CLAUDE_MD_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.status === 200 && result.body && !looksLikeHtml(result.body)) {
        return [{
          id: generateId(),
          checkId: 'CLAUDE-MD-EXPOSED',
          severity: 'high',
          title: 'CLAUDE.md System Instructions Exposed',
          description: 'Agent system instructions file is publicly accessible',
          port,
          path,
          evidence: `Found CLAUDE.md at ${path}`,
          impact: 'System instructions reveal agent behavior, capabilities, and potential weaknesses',
          fix: 'Remove file from public access or configure web server to deny access',
        }];
      }
    }
    return [];
  }

  private async probeRootForApiKeys(baseUrl: string, port: number, timeout: number, insecure: boolean): Promise<ExternalFinding[]> {
    const rootResult = await this.httpProbe(baseUrl + '/', timeout, insecure);
    if (rootResult && rootResult.body) {
      for (const { name, pattern } of API_KEY_PATTERNS) {
        if (pattern.test(rootResult.body)) {
          return [{
            id: generateId(),
            checkId: 'API-KEY-EXPOSED',
            severity: 'critical',
            title: `${name} API Key Exposed`,
            description: `${name} API key found in HTTP response`,
            port,
            path: '/',
            evidence: `Found ${name} API key pattern in response`,
            impact: 'API keys can be used to access services, incur costs, or steal data',
            fix: 'Remove API keys from responses and rotate compromised keys',
          }];
        }
      }
    }
    return [];
  }

  private httpProbe(
    url: string,
    timeout: number,
    insecure = false
  ): Promise<{ status: number; contentType?: string; body?: string } | null> {
    return new Promise((resolve) => {
      const isHttps = url.startsWith('https://');
      const client = isHttps ? https : http;
      let settled = false;
      let deadline: NodeJS.Timeout | undefined;
      const finish = (value: { status: number; contentType?: string; body?: string } | null) => {
        if (settled) return;
        settled = true;
        if (deadline) clearTimeout(deadline);
        resolve(value);
      };

      const req = client.get(
        url,
        {
          timeout,
          headers: {
            'User-Agent': 'HackMyAgent-Scanner/1.0',
            'ngrok-skip-browser-warning': 'true',
          },
          rejectUnauthorized: !insecure,
        },
        (res) => {
          let body = '';
          const answer = () => finish({
            status: res.statusCode ?? 0,
            contentType: res.headers['content-type'],
            body: body.substring(0, 10000),
          });
          res.on('data', (chunk) => {
            body += chunk;
            // Limit body size. Answer with what was read BEFORE destroying the
            // stream: a destroyed response emits neither 'end' nor 'error', so
            // the probe used to sit out its whole deadline on any page over
            // the cap -- six of those per port is the 12 s a live site took.
            if (body.length > 10000) {
              answer();
              res.destroy();
            }
          });
          res.on('end', answer);
          res.on('error', () => finish(null));
          res.on('close', () => finish(null));
        }
      );

      // `timeout` above is an IDLE timeout: a server that accepts the socket
      // and keeps it open without a byte never trips it. Bound the request
      // end to end as well, so one held connection cannot eat the scan.
      deadline = setTimeout(() => {
        req.destroy();
        finish(null);
      }, timeout);

      req.on('timeout', () => {
        req.destroy();
        finish(null);
      });

      req.on('error', () => finish(null));
    });
  }
}
