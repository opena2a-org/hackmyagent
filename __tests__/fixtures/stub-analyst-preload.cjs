/**
 * Answers every Layer 3 HTTP call with one fixed response shape, so a test can
 * vary the ANALYST'S FORMATTING and nothing else.
 *
 * A preload rather than a module mock because the test spawns the real CLI: the
 * claim under test is an exit code, and an exit code is only real at a process
 * boundary. Patching `globalThis.fetch` also guarantees the suite makes no
 * network call and needs no API key.
 */
const SHAPE = process.env.HMA_STUB_ANALYST_RESPONSE;
if (typeof SHAPE === 'string') {
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      content: [{ type: 'text', text: SHAPE }],
      usage: { input_tokens: 10, output_tokens: 5 },
      model: 'stub',
    }),
    text: async () => '{}',
  });
}
