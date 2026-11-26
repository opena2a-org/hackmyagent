/**
 * A2A-002 reports an unauthenticated handler of the task submission of
 * A2A v0.3.0 (the message/send JSON-RPC method) and v1.0 (the SendMessage
 * method, or the POST /message:send route), as it does /tasks/send, and
 * does not report one behind authentication.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

async function a2a002(file: string, body: string): Promise<any[]> {
  const dir = tempDir('hma-a2a002-');
  await fs.writeFile(path.join(dir, file), body);
  const drafts: any[] = await (new HardeningScanner() as any).checkA2AExposure(dir, false);
  return drafts.filter((f) => f.checkId === 'A2A-002' && !f.passed);
}

const HANDLERS: Record<string, { file: string; body: string; line: number }> = {
  'message/send (v0.3.0)': {
    file: 'server.ts',
    body: [
      "import express from 'express';",
      'const app = express();',
      "app.post('/', (req, res) => {",
      "  if (req.body.method === 'message/send') return res.json(run(req.body));",
      '});',
    ].join('\n'),
    line: 4,
  },
  'SendMessage (v1.0 JSON-RPC)': {
    file: 'server.ts',
    body: [
      'const handlers = {',
      '  "SendMessage": (params) => run(params),',
      '};',
    ].join('\n'),
    line: 2,
  },
  'POST /message:send (v1.0 HTTP+JSON)': {
    file: 'server.ts',
    body: [
      "import express from 'express';",
      'const app = express();',
      "app.post('/message\\\\:send', (req, res) => res.json(run(req.body)));",
    ].join('\n'),
    line: 3,
  },
  'POST /message:send in Python': {
    file: 'server.py',
    body: [
      'app = FastAPI()',
      '',
      '@app.post("/v1/message:send")',
      'def send(req):',
      '    return run(req)',
    ].join('\n'),
    line: 3,
  },
};

describe('A2A-002 on v0.3.0 and v1.0 task submission', () => {
  for (const [name, { file, body, line }] of Object.entries(HANDLERS)) {
    it(`reports an unauthenticated ${name} handler`, async () => {
      const hits = await a2a002(file, body + '\n');
      expect(hits.map((f) => [f.file, f.line])).toEqual([[file, line]]);
    });

    it(`does not report an authenticated ${name} handler`, async () => {
      const guarded = 'app.use(requireBearerToken);\n' + body + '\n';
      expect(await a2a002(file, guarded)).toEqual([]);
    });
  }

  it('does not take a sendMessage call or a SendMessage type for a handler', async () => {
    const body = [
      'interface SendMessage { text: string }',
      "bot.sendMessage(chatId, 'message sent');",
    ].join('\n');
    expect(await a2a002('server.ts', body + '\n')).toEqual([]);
  });
});
