import http from 'http';

interface ChatResponse {
  id: string;
  choices: Array<{
    message: { role: string; content: string };
    finish_reason: string;
  }>;
}

interface MCPToolResponse {
  success: boolean;
  content?: string;
  output?: string;
  results?: unknown[];
  note?: string;
}

interface HealthResponse {
  status: string;
  agent: string;
  port: number;
}

interface StatsResponse {
  totalRequests: number;
  attacksDetected: number;
  attacksSuccessful: number;
}

/**
 * HTTP client for DVAA agent endpoints.
 */
export class DVAAClient {
  /** Send a chat message to an API agent */
  async chat(port: number, message: string): Promise<ChatResponse> {
    return this.post<ChatResponse>(port, '/v1/chat/completions', {
      messages: [{ role: 'user', content: message }],
    });
  }

  /** Execute an MCP tool on an MCP agent */
  async mcpExecute(port: number, tool: string, args: Record<string, unknown>): Promise<MCPToolResponse> {
    return this.post<MCPToolResponse>(port, '/mcp/execute', {
      tool,
      arguments: args,
    });
  }

  /** Send an A2A message */
  async a2aMessage(port: number, from: string, message: string): Promise<ChatResponse> {
    return this.post<ChatResponse>(port, '/v1/chat/completions', {
      messages: [
        { role: 'system', content: `Message from agent: ${from}` },
        { role: 'user', content: message },
      ],
    });
  }

  /** Health check */
  async health(port: number): Promise<HealthResponse> {
    return this.get<HealthResponse>(port, '/health');
  }

  /** Get stats */
  async stats(port: number): Promise<StatsResponse> {
    return this.get<StatsResponse>(port, '/stats');
  }

  private get<T>(port: number, path: string): Promise<T> {
    return new Promise((resolve, reject) => {
      const req = http.get(`http://localhost:${port}${path}`, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body) as T);
          } catch {
            reject(new Error(`Invalid JSON from port ${port}${path}: ${body.slice(0, 200)}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(10000, () => {
        req.destroy();
        reject(new Error(`Request to port ${port}${path} timed out`));
      });
    });
  }

  private post<T>(port: number, path: string, body: unknown): Promise<T> {
    const payload = JSON.stringify(body);

    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: 'localhost',
          port,
          path,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            try {
              resolve(JSON.parse(data) as T);
            } catch {
              reject(new Error(`Invalid JSON from port ${port}${path}: ${data.slice(0, 200)}`));
            }
          });
        },
      );

      req.on('error', reject);
      req.setTimeout(10000, () => {
        req.destroy();
        reject(new Error(`POST to port ${port}${path} timed out`));
      });

      req.write(payload);
      req.end();
    });
  }
}
