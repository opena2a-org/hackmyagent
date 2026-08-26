/**
 * Captures every outbound fetch the spawned CLI makes and answers it with a
 * generic 200, so a `--publish` run is hermetic and the test can read the
 * exact wire payload the Registry would have received.
 *
 * A preload rather than a module mock because the claim under test is the
 * byte-level publish payload at the process boundary: `secure --publish`
 * routes through dist/registry/publish.js -> dist/registry/client.js, whose
 * network primitive is global fetch (client.ts:349 POST /api/v1/trust/publish).
 * Stubbing fetch intercepts every path (unified, legacy fallback,
 * reportFindings/reportRemediation) without touching the module graph.
 *
 * Gated on HMA_STUB_REGISTRY_CAPTURE: the path of an append-only JSONL file,
 * one line per request: {"url": ..., "method": ..., "body": ...}.
 */
const { appendFileSync } = require('node:fs');

const CAPTURE = process.env.HMA_STUB_REGISTRY_CAPTURE;
if (typeof CAPTURE === 'string' && CAPTURE.length > 0) {
  globalThis.fetch = async (url, init) => {
    const record = {
      url: String(url),
      method: (init && init.method) || 'GET',
      body: init && typeof init.body === 'string' ? init.body : null,
    };
    appendFileSync(CAPTURE, JSON.stringify(record) + '\n');
    return {
      ok: true,
      status: 200,
      // Superset shape: enough for RegistryClient's unified-publish read
      // (profileUrl/consensusStatus) and inert for any other caller.
      json: async () => ({
        profileUrl: 'https://registry.stub/agents/stub',
        consensusStatus: 'accepted',
        success: true,
      }),
      text: async () => '{"success":true}',
    };
  };
}
