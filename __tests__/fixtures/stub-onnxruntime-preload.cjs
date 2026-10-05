/**
 * Stands in for onnxruntime-node, so a spawned scan can open and release an
 * ONNX session without the native library or the downloaded model.
 *
 * Each session writes one stderr line when it is created and one when it is
 * released. Both use `fs.writeSync`, because the release under test runs in a
 * `process` `exit` listener, where an asynchronous write may never be flushed.
 *
 * Like the real one, `release()` does its work before its first `await`:
 * onnxruntime-node disposes the native session synchronously inside an async
 * `release()`, and the CLI relies on that when it releases from `exit`.
 */
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const resolved = require.resolve('onnxruntime-node', {
  paths: [path.join(__dirname, '..', '..')],
});

let created = 0;

const stub = new Module(resolved);
stub.filename = resolved;
stub.loaded = true;
stub.exports = {
  env: {},
  Tensor: class Tensor {
    constructor(type, data, dims) {
      this.type = type;
      this.data = data;
      this.dims = dims;
    }
  },
  InferenceSession: {
    async create() {
      created += 1;
      const id = created;
      fs.writeSync(2, `ORT-STUB created ${id}\n`);
      return {
        // All-zero logits are a uniform distribution, which classifies as benign.
        async run() {
          return { logits: { data: new Float32Array(10) } };
        },
        async release() {
          fs.writeSync(2, `ORT-STUB released ${id}\n`);
        },
      };
    },
  },
};

require.cache[resolved] = stub;
