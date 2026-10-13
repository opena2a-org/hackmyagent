/**
 * #770: the preload scan-soul-deep-series.mjs loads into its measurement run.
 *
 * It answers every request to the hosted-model API in-process, so the run
 * sends nothing there and costs nothing, and it appends one JSON line per
 * event to the file named in HMA_DEEP_SERIES_MEASURE_FILE:
 *
 *   {"loaded":true}     once, when this file runs. Its absence tells the
 *                       series script that nothing below was counted.
 *   {"request":{...}}   per hosted-model request: the model it names, the
 *                       output tokens it asks for and the bytes of its prompt.
 *   {"session":true}    per session onnxruntime-node creates.
 *
 * Requests to any other host go to the real `fetch`, because the scan may
 * have to download the classifier model before it can open a session.
 *
 * Every line is written with a synchronous append, so a run that ends without
 * warning still leaves what it did.
 */
const fs = require('node:fs');
const Module = require('node:module');

const HOSTED_API = 'https://api.anthropic.com/';
const out = process.env.HMA_DEEP_SERIES_MEASURE_FILE;

function record(entry) {
  fs.appendFileSync(out, `${JSON.stringify(entry)}\n`);
}

/** The bytes of every text the request sends as prompt, or of the whole body when it cannot be read. */
function describeRequest(body) {
  const text = typeof body === 'string' ? body : '';
  try {
    const parsed = JSON.parse(text);
    let promptBytes = 0;
    const add = (value) => {
      if (typeof value === 'string') promptBytes += Buffer.byteLength(value);
      else if (Array.isArray(value)) value.forEach((part) => add(part && typeof part === 'object' ? part.text : part));
    };
    add(parsed.system);
    for (const message of Array.isArray(parsed.messages) ? parsed.messages : []) add(message && message.content);
    return { model: parsed.model ?? null, maxTokens: parsed.max_tokens ?? null, promptBytes };
  } catch {
    return { model: null, maxTokens: null, promptBytes: Buffer.byteLength(text) };
  }
}

if (out) {
  record({ loaded: true });

  const realFetch = globalThis.fetch;
  globalThis.fetch = async function measuredFetch(input, init) {
    const url = typeof input === 'string' ? input : String((input && input.url) || input);
    if (!url.startsWith(HOSTED_API)) return realFetch.call(this, input, init);
    record({ request: describeRequest(init && init.body) });
    return new Response(JSON.stringify({ content: [{ type: 'text', text: 'NO' }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  const wrapped = new WeakSet();
  const realLoad = Module._load;
  Module._load = function measuredLoad(request, parent, isMain) {
    const loaded = realLoad.call(this, request, parent, isMain);
    const sessions = request === 'onnxruntime-node' && loaded ? loaded.InferenceSession : null;
    if (sessions && typeof sessions.create === 'function' && !wrapped.has(sessions)) {
      wrapped.add(sessions);
      const realCreate = sessions.create;
      sessions.create = async function measuredCreate(...args) {
        const session = await realCreate.apply(this, args);
        record({ session: true });
        return session;
      };
    }
    return loaded;
  };
}
