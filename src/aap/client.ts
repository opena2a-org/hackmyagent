/**
 * AAP grant client for hackmyagent.
 *
 * Speaks the Agent Authorization Protocol wire format to a local Secretless broker
 * over its Unix socket (HTTP over AF_UNIX). The agent presents an ATX, references a
 * grant (grant://...), and asks the broker to authorize a logical operation. The
 * broker returns ONLY the operation result; no credential or backend identifier
 * crosses back into agent context (AAP §4).
 *
 * Mirrors `opena2a-cli/packages/cli/src/aap/client.ts` (the first TypeScript AAP
 * consumer, opena2a-org/opena2a#179). Both modules will fold into a shared
 * `@opena2a/aap-client` package once both consumers are stable; until then this
 * is a deliberate copy so each repo can iterate independently. Any change here
 * MUST also land in opena2a-cli's copy.
 *
 * Shape mirrors `agent-identity-management/sdk/python/aim_sdk/grant_client.py` so
 * the TS + Python surfaces stay aligned. AAP §6 defines the wire format. AAP §6.6
 * defines uniform opaque denial: a 403 response carries `{error: "denied"}` and
 * nothing else; this client raises `GrantDeniedError` with no detail.
 */
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

export const DEFAULT_SOCKET_PATH = path.join(os.homedir(), '.secretless-ai', 'broker.sock');
export const DEFAULT_TOKEN_PATH = path.join(os.homedir(), '.secretless-ai', 'broker.token');

const MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MiB cap on broker response

export class BrokerGrantError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'BrokerGrantError';
  }
}

export class GrantDeniedError extends BrokerGrantError {
  constructor(public readonly grant: string) {
    super(`grant denied: ${grant}`);
    this.name = 'GrantDeniedError';
  }
}

/**
 * A broker responded with an unexpected status (not 200/401/403). Carries the
 * status code but NEVER the response body: AAP §6.6 says the consumer must not
 * surface broker-side detail, and a misbehaving or impostor broker can return
 * sensitive content (cross-tenant table names, queries, hosts) in a 5xx body.
 */
export class BrokerUnexpectedStatusError extends BrokerGrantError {
  constructor(public readonly status: number) {
    super(`broker returned unexpected status ${status}`);
    this.name = 'BrokerUnexpectedStatusError';
  }
}

export interface BrokerClientOptions {
  socketPath?: string;
  httpUrl?: string;
  token?: string;
  tokenPath?: string;
  timeoutMs?: number;
}

export interface GrantOperation {
  method: string;
  path: string;
  query?: Record<string, string>;
  body?: unknown;
}

export interface GrantRequest {
  agentId: string;
  atx: Record<string, unknown>;
  grant: string;
  operation: GrantOperation;
}

export class BrokerClient {
  readonly socketPath: string;
  readonly httpUrl?: string;
  readonly timeoutMs: number;
  private readonly explicitToken?: string;
  private readonly tokenPath: string;

  constructor(options: BrokerClientOptions = {}) {
    this.socketPath = options.socketPath ?? DEFAULT_SOCKET_PATH;
    this.httpUrl = options.httpUrl;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.explicitToken = options.token;
    this.tokenPath = options.tokenPath ?? DEFAULT_TOKEN_PATH;
  }

  private readToken(): string {
    if (this.explicitToken) return this.explicitToken;
    try {
      return fs.readFileSync(this.tokenPath, 'utf-8').trim();
    } catch (err) {
      throw new BrokerGrantError(
        `broker token not found at ${this.tokenPath}; is the broker running?`,
        err,
      );
    }
  }

  async grant(req: GrantRequest): Promise<unknown> {
    const body = JSON.stringify(req);
    const token = this.readToken();
    const headers: http.OutgoingHttpHeaders = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      Authorization: `Bearer ${token}`,
    };

    const { status, text } = await this.requestRaw('/grant', headers, body);

    if (status === 200) {
      let parsed: { result?: unknown };
      try {
        parsed = JSON.parse(text);
      } catch (err) {
        throw new BrokerGrantError('broker returned non-JSON success body', err);
      }
      return parsed.result;
    }
    if (status === 403) {
      throw new GrantDeniedError(req.grant);
    }
    if (status === 401) {
      throw new BrokerGrantError('broker rejected token (401); rotate broker.token');
    }
    // AAP §6.6: do NOT interpolate the broker response body into the error
    // surface. A non-403 response can carry sensitive broker-side context
    // (cross-tenant detail, host names, query strings) that the consumer must
    // not echo. The status code alone is enough for the user to triage.
    throw new BrokerUnexpectedStatusError(status);
  }

  private requestRaw(
    urlPath: string,
    headers: http.OutgoingHttpHeaders,
    body: string,
  ): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const requestOptions: http.RequestOptions = this.httpUrl
        ? httpUrlToOptions(this.httpUrl, urlPath, headers)
        : { socketPath: this.socketPath, path: urlPath, method: 'POST', headers };

      const req = http.request(requestOptions, (res) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        let oversized = false;
        res.on('data', (c: Buffer) => {
          bytes += c.length;
          if (bytes > MAX_RESPONSE_BYTES) {
            if (!oversized) {
              oversized = true;
              req.destroy(new Error('broker response exceeded 1MiB cap'));
            }
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => {
          if (oversized) return; // req.destroy already rejected
          resolve({
            status: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString('utf-8'),
          });
        });
        res.on('error', (err) => reject(new BrokerGrantError(`broker response error: ${err.message}`, err)));
      });

      req.setTimeout(this.timeoutMs, () => {
        req.destroy(new Error(`broker request timed out after ${this.timeoutMs}ms`));
      });
      req.on('error', (err) => reject(new BrokerGrantError(`could not reach broker: ${err.message}`, err)));
      req.write(body);
      req.end();
    });
  }
}

function httpUrlToOptions(
  url: string,
  urlPath: string,
  headers: http.OutgoingHttpHeaders,
): http.RequestOptions {
  const parsed = new URL(url);
  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: urlPath,
    method: 'POST',
    headers,
  };
}
