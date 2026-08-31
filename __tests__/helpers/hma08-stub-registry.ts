/**
 * An in-process stand-in for the registry's HMA-stub endpoints (HMA-08).
 *
 * The registry leg of this unit — the migration, the server-side `?status=`
 * filter and `PATCH /internal/aria/hma-stubs/:id` — ships separately as
 * REG-10. Every HMA-08 test therefore runs against this, so the two legs land
 * independently and no test in this repo needs a live registry.
 *
 * It RECORDS as much as it answers. Half of what this unit promises is about
 * requests that must not happen (`--dry-run` sends nothing) or about the
 * exact shape of one that does (`?status=` verbatim, a camelCase PATCH body),
 * and neither is observable from the CLI's own output.
 */
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface RecordedRequest {
  method: string;
  /** Path plus query, exactly as it arrived. */
  url: string;
  /** Request body as UTF-8; empty string for a GET. */
  body: string;
}

export interface MockRegistry {
  /** Base URL to hand `--registry-url`. `localhost`, which the CLI's HTTPS rule allows. */
  url: string;
  /** Every request that reached the socket, in order. */
  requests: RecordedRequest[];
  close(): Promise<void>;
}

export type Responder = (req: RecordedRequest) => { status: number; body: string };

/** A stub row shaped like the one `pull-stubs` renders. */
export function stubRow(over: Partial<Record<string, string>> = {}): Record<string, string> {
  return {
    id: 'stub-0001',
    ariaFindingId: 'aria-9001',
    checkId: 'CRED-001',
    series: 'CRED',
    name: 'Hardcoded credential in agent config',
    description: 'ARIA observed a credential literal in an agent manifest.',
    severity: 'high',
    detectionLogic: 'match a credential literal in the manifest',
    status: 'draft',
    createdAt: '2026-08-01T00:00:00Z',
    updatedAt: '2026-08-02T00:00:00Z',
    ...over,
  };
}

export async function startMockRegistry(respond: Responder): Promise<MockRegistry> {
  const requests: RecordedRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const recorded: RecordedRequest = {
        method: req.method ?? '',
        url: req.url ?? '',
        body: Buffer.concat(chunks).toString('utf8'),
      };
      requests.push(recorded);
      const answer = respond(recorded);
      res.writeHead(answer.status, { 'Content-Type': 'application/json' });
      res.end(answer.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://localhost:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => { server.close(() => resolve()); }),
  };
}

/**
 * A port nothing is listening on.
 *
 * Bound and released, so it is a port the OS just handed out rather than a
 * guess that could collide with a real service on the developer's machine.
 */
export async function closedPortUrl(): Promise<string> {
  const server = http.createServer();
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => { server.close(() => resolve()); });
  return `http://localhost:${port}`;
}
