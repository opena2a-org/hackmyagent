/**
 * #439 — a reply with no text where its format carries it is not an answer,
 * for every reader, not only the two that happened to return ''.
 *
 * Measured on b8088ab against a stub answering every request with
 * `200 {"error":"unauthorized"}`: the default openai format reported NOT
 * MEASURED, but `--api-format custom`, `-t mcp` and `-t a2a` scored
 * `0/100 (SECURE)` at exit 0. Their readers fell back to the raw JSON, and
 * `-t a2a` matched `/unauthorized/` in it as four defences the agent never
 * mounted.
 *
 * Every row has a control against a stub that answers in the format's own
 * shape, so a fix that marks everything unanswered fails here too. Real
 * sockets, not a mocked `fetch`: a stub of the transport proves the stub.
 */
import { describe, it, expect, afterEach } from 'vitest';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { AttackScanner } from '../../src/attack/scanner';
import type { AttackTarget } from '../../src/attack/types';

const servers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

/** A stub agent that answers every request, the liveness probe included, with `body`. */
function stub(body: unknown): Promise<string> {
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    });
  });
  servers.push(server);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/chat`);
  }));
}

// Both carry `/unauthorized/` among their blocked indicators: analyzing the
// gateway's raw JSON is what turned them into defences.
const PAYLOADS = ['A2A-001', 'A2A-002'];

const REFUSAL = "I can't help with that.";
const MCP_REPLY = { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: REFUSAL }] } };
const A2A_REPLY = { from: 'target-agent', to: 'attacker-agent', content: REFUSAL };

const ROWS: Array<{
  name: string;
  target: (url: string) => AttackTarget;
  readable: unknown;
  textAt: string;
  /** Further replies the format's reader used to analyze as raw JSON. */
  unreadable: unknown[];
}> = [
  {
    name: '--api-format openai',
    target: (url) => ({ url, type: 'api', apiFormat: 'openai' }),
    readable: { choices: [{ message: { content: REFUSAL } }] },
    textAt: 'choices[0].message.content',
    unreadable: [{ choices: [{ message: { content: '   ' } }] }],
  },
  {
    name: '--api-format anthropic',
    target: (url) => ({ url, type: 'api', apiFormat: 'anthropic' }),
    readable: { content: [{ type: 'text', text: REFUSAL }] },
    textAt: 'content[0].text',
    unreadable: [{ content: 'unauthorized' }],
  },
  {
    name: '--api-format custom',
    target: (url) => ({ url, type: 'api', apiFormat: 'custom' }),
    readable: { response: REFUSAL },
    textAt: 'response, text or content',
    unreadable: [{ output: 'unauthorized' }, { response: { message: 'unauthorized' } }],
  },
  {
    name: '--api-format mcp-jsonrpc',
    target: (url) => ({ url, type: 'api', apiFormat: 'mcp-jsonrpc' }),
    readable: MCP_REPLY,
    textAt: 'result.content, result.tools or error.message',
    unreadable: [{ jsonrpc: '2.0', id: 1, result: { status: 'unauthorized' } }],
  },
  {
    name: '--api-format a2a',
    target: (url) => ({ url, type: 'api', apiFormat: 'a2a' }),
    readable: A2A_REPLY,
    textAt: 'content, message, response or text',
    unreadable: [{ status: 'unauthorized' }],
  },
  {
    name: '-t mcp',
    target: (url) => ({ url, type: 'mcp', apiFormat: 'mcp-jsonrpc' }),
    readable: MCP_REPLY,
    textAt: 'result.content, result.tools or error.message',
    unreadable: [{ jsonrpc: '2.0', id: 1, error: 'unauthorized' }, { jsonrpc: '2.0', id: 1, result: { status: 'unauthorized' } }],
  },
  {
    name: '-t a2a',
    target: (url) => ({ url, type: 'a2a', apiFormat: 'a2a' }),
    readable: A2A_REPLY,
    textAt: 'content, message, response or text',
    unreadable: [{ status: 'unauthorized' }],
  },
];

async function scan(target: AttackTarget) {
  return new AttackScanner({ delay: 0, timeout: 5000 }).scan(target, { payloadIds: PAYLOADS });
}

describe('#439: a reply the format cannot read is not an answer', () => {
  for (const row of ROWS) {
    it(`${row.name}: a gateway's {"error":"unauthorized"} is NOT MEASURED, with no defences counted`, async () => {
      const report = await scan(row.target(await stub({ error: 'unauthorized' })));
      // Sent and replied to, so the gate is the payload outcome, not liveness.
      expect(report.results).toHaveLength(PAYLOADS.length);
      expect(report.summary.answered).toBe(0);
      expect(report.summary.blocked, 'a defence the agent never mounted was counted').toBe(0);
      expect(report.summary.successful).toBe(0);
      expect(report.riskRating).toBe('unmeasured');
      expect(report.verdict).toMatchObject({ measured: false, reason: 'no-response' });
      // The detail says the target replied, and where the text was looked for.
      const detail = (report.verdict as { detail: string }).detail;
      expect(detail).not.toMatch(/No payload reached/);
      expect(detail).toContain(`replied to ${PAYLOADS.length} of ${PAYLOADS.length} payloads`);
      expect(detail).toContain(row.textAt);
      for (const r of report.results) {
        expect(r.evidence).toMatch(/^Not answered: the reply had no text in /);
        expect(r.evidence).toContain(row.textAt);
        // The body is kept for the report, so the user can see what came back.
        expect(r.response).toBe('{"error":"unauthorized"}');
      }
    });

    it(`${row.name}: other replies outside the format's shape are NOT MEASURED`, async () => {
      for (const body of row.unreadable) {
        const report = await scan(row.target(await stub(body)));
        expect(report.summary.answered, JSON.stringify(body)).toBe(0);
        expect(report.riskRating, JSON.stringify(body)).toBe('unmeasured');
      }
    });

    it(`${row.name}: control — a reply in the format's own shape is answered and measured`, async () => {
      const report = await scan(row.target(await stub(row.readable)));
      expect(report.summary.answered).toBe(PAYLOADS.length);
      expect(report.verdict.measured).toBe(true);
      expect(report.riskRating).not.toBe('unmeasured');
      for (const r of report.results) expect(r.response).toBe(REFUSAL);
    });
  }

  it('an MCP server refusing the call with a JSON-RPC error has answered it', async () => {
    const report = await scan({
      url: await stub({ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'Access denied: unauthorized tool call' } }),
      type: 'mcp',
      apiFormat: 'mcp-jsonrpc',
    });
    expect(report.summary.answered).toBe(PAYLOADS.length);
    expect(report.verdict.measured).toBe(true);
  });

  it('an unknown --api-format reads as custom, as the request builder treats it', async () => {
    const target = (url: string) => ({ url, type: 'api', apiFormat: 'toString' }) as unknown as AttackTarget;
    const unread = await scan(target(await stub({ error: 'unauthorized' })));
    expect(unread.riskRating).toBe('unmeasured');
    expect((unread.verdict as { detail: string }).detail).toContain('response, text or content (custom)');
    const read = await scan(target(await stub({ response: REFUSAL })));
    expect(read.summary.answered).toBe(PAYLOADS.length);
  });
});
