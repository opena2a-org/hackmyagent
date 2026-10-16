'use strict';
// Answers the analysis provider on this machine and records what each request
// would have carried, preloaded with
//
//   NODE_OPTIONS='--require "__tests__/helpers/provider-capture.cjs"' node dist/cli.js secure <dir> --deep
//
// It fails closed in two layers:
//
// - `loopback-only.cjs` refuses every TCP connection to a host that is not
//   loopback, before the name is looked up. A request path this file does not
//   patch still cannot leave the machine; it fails as a refused connection.
// - `globalThis.fetch` is replaced. A request to `*.anthropic.com` is answered
//   here: a `report_findings` call with no findings when the request offers
//   that tool, the text `NO` otherwise. Every other fetch, loopback included,
//   fails as a refused connection does, so a NanoMind daemon or Ollama running
//   on the machine that runs the suite cannot take the requests instead and
//   change what is counted.
//
// Each provider request is appended to $HMA_TEST_PROVIDER_LOG as one JSON line
// holding the request body. The API key header is never recorded, only whether
// one was sent. The preload refuses to load without a log path, because a
// capture nobody can read proves nothing.
//
// Each line also lists the send notices (`[Label] Sending N files to ...`) the
// process had written to stderr before that request, so a test can show the
// notice came first rather than only that it appeared somewhere.

require('./loopback-only.cjs');

const fs = require('node:fs');

const LOG = process.env.HMA_TEST_PROVIDER_LOG;
if (!LOG) {
  throw new Error('provider-capture.cjs: HMA_TEST_PROVIDER_LOG is not set, so nothing this run sends could be read back');
}

const PROVIDER = /(^|\.)anthropic\.com$/i;
const NOTICE = /^(\[[^\]]+\]) Sending \d+ files? to \S+ in \d+ requests?, because ANTHROPIC_API_KEY is set\./gm;

const noticesSeen = [];
const stderrWrite = process.stderr.write;
process.stderr.write = function noticeRecordingWrite(chunk, ...rest) {
  for (const m of String(chunk).matchAll(NOTICE)) noticesSeen.push(m[1]);
  return stderrWrite.call(this, chunk, ...rest);
};

function record(entry) {
  fs.appendFileSync(LOG, JSON.stringify(entry) + '\n');
}

async function bodyText(body) {
  if (body === undefined || body === null) return '';
  if (typeof body === 'string') return body;
  return Buffer.from(await new Response(body).arrayBuffer()).toString('utf8');
}

globalThis.fetch = async function capturedFetch(input, init = {}) {
  const href = typeof input === 'string' ? input : (input && input.url) || String(input);
  const url = new URL(href);
  if (!PROVIDER.test(url.hostname)) {
    throw new TypeError('fetch failed', {
      cause: Object.assign(new Error(`connect ECONNREFUSED ${url.host} (only the provider is answered under this preload)`), {
        code: 'ECONNREFUSED',
      }),
    });
  }

  const body = await bodyText(init.body);
  let parsed = null;
  try { parsed = JSON.parse(body); } catch { /* recorded as text */ }
  const headers = new Headers(init.headers || {});
  const tools = parsed && Array.isArray(parsed.tools) ? parsed.tools : [];
  record({
    host: url.hostname,
    path: url.pathname,
    keySent: Boolean(headers.get('x-api-key')),
    tool: tools.length > 0 ? String(tools[0].name) : null,
    body,
    noticesBefore: [...noticesSeen],
  });

  const content = tools.length > 0
    ? [{ type: 'tool_use', id: 'toolu_capture', name: tools[0].name, input: { findings: [] } }]
    : [{ type: 'text', text: 'NO' }];
  return new Response(JSON.stringify({
    id: 'msg_capture',
    type: 'message',
    role: 'assistant',
    model: (parsed && parsed.model) || 'capture',
    content,
    stop_reason: tools.length > 0 ? 'tool_use' : 'end_turn',
    stop_sequence: null,
    usage: { input_tokens: 1, output_tokens: 1 },
  }), { status: 200, headers: { 'content-type': 'application/json' } });
};
