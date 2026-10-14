/**
 * Answers every Layer 3 HTTP call with one fixed response shape, so a test can
 * vary the ANALYST'S FORMATTING and nothing else.
 *
 * A preload rather than a module mock because the test spawns the real CLI: the
 * claim under test is an exit code, and an exit code is only real at a process
 * boundary. Patching `globalThis.fetch` also guarantees the suite makes no
 * network call and needs no API key.
 *
 * Two ways to set the answer:
 *   HMA_STUB_ANALYST_RESPONSE  a reply that is text only, ending the turn
 *   HMA_STUB_ANALYST_MESSAGE   a JSON object `{ content, stop_reason }`, for a
 *                              reply carrying tool calls or another stop reason
 */
const SHAPE = process.env.HMA_STUB_ANALYST_RESPONSE;
const MESSAGE = process.env.HMA_STUB_ANALYST_MESSAGE;

function answerWith(message) {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      ...message,
      usage: { input_tokens: 10, output_tokens: 5 },
      model: 'stub',
    }),
    text: async () => '{}',
  });
}

if (typeof SHAPE === 'string') {
  answerWith({ content: [{ type: 'text', text: SHAPE }], stop_reason: 'end_turn' });
} else if (typeof MESSAGE === 'string') {
  answerWith(JSON.parse(MESSAGE));
} else if (process.env.HMA_STUB_ANALYST_THROW) {
  // #479 — the call itself fails, as a network outage or a refused connection
  // does: no response at all, rather than a response that cannot be read.
  globalThis.fetch = async () => {
    throw new TypeError('fetch failed');
  };
}
