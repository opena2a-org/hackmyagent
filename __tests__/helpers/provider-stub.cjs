'use strict';
// Answers the analysis provider locally, preloaded into a spawned CLI after
// loopback-only.cjs:
//
//   NODE_OPTIONS='--require "__tests__/helpers/loopback-only.cjs" --require "__tests__/helpers/provider-stub.cjs"' \
//     node dist/cli.js secure <dir> --deep
//
// `fetch` to a `*.anthropic.com` host is answered here. A request that offers
// tools gets one call to the first tool it offers, whose `findings` are the
// JSON array in $HMA_TEST_PROVIDER_FINDINGS (empty when unset). A request that
// offers none gets the text `NO`. `fetch` to any other host that is not
// loopback gets a local 404. A connection made some other way is refused by
// loopback-only.cjs, so nothing this process opens leaves the machine.
//
// When $HMA_TEST_PROVIDER_LOG names a file, each answered request is appended
// to it as one JSON line `{ url, body }`. The key header is never recorded.

const fs = require('node:fs');

const LOG = process.env.HMA_TEST_PROVIDER_LOG;
const FINDINGS = JSON.parse(process.env.HMA_TEST_PROVIDER_FINDINGS || '[]');
const realFetch = globalThis.fetch;

function hostOf(input) {
  try {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    return { url, host: new URL(url).hostname.toLowerCase() };
  } catch {
    return { url: String(input), host: '' };
  }
}

function isLoopback(host) {
  const h = host.replace(/^\[(.*)\]$/, '$1');
  return h === 'localhost' || h === '::1' || /^127(\.\d{1,3}){3}$/.test(h);
}

function reply(request) {
  const tool = Array.isArray(request.tools) && request.tools[0];
  const content = tool
    ? [{ type: 'tool_use', id: 'toolu_stub', name: tool.name, input: { findings: FINDINGS } }]
    : [{ type: 'text', text: 'NO' }];
  return {
    id: 'msg_stub',
    type: 'message',
    role: 'assistant',
    model: 'stub',
    stop_reason: tool ? 'tool_use' : 'end_turn',
    content,
    usage: { input_tokens: 1, output_tokens: 1 },
  };
}

globalThis.fetch = async function (input, init) {
  const { url, host } = hostOf(input);
  if (host === 'anthropic.com' || host.endsWith('.anthropic.com')) {
    const body = init && init.body !== undefined ? String(init.body) : '';
    if (LOG) {
      try {
        fs.appendFileSync(LOG, JSON.stringify({ url, body }) + '\n');
      } catch {
        // Never let the record change the behaviour of the CLI under test.
      }
    }
    let request = {};
    try { request = JSON.parse(body); } catch { /* answered as a request without tools */ }
    return new Response(JSON.stringify(reply(request)), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  if (isLoopback(host)) return realFetch.call(this, input, init);
  return new Response('not found (answered locally by provider-stub.cjs)', { status: 404 });
};
