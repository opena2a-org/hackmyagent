/**
 * The classifier's ONNX session is created from the bytes that passed their
 * pinned check, never from the files' paths.
 *
 * Created from a path, onnxruntime opened `nanomind-tme.onnx` again after the
 * check and opened `nanomind-tme.onnx.data` beside it by itself, so a file
 * changed between the check and the parse was parsed unchecked. Measured on
 * the released model: a 4 kB block of the weights changed at that point
 * turned the verdict on one text from injection at 0.99997 into
 * credential_abuse at 0.96190. The tokenizer was parsed from a read of its
 * own, with the same gap.
 *
 * WHAT THIS TEST RUNS. The real onnxruntime-node, on a model built here: a
 * graph whose `logits` output is one 1x10 weights tensor kept in the external
 * data file, so the verdict comes from those bytes alone. Each file is padded
 * to its pinned size, and `hashFileBytes` reads a file's sha256 as the pinned
 * value only while its bytes are the bytes written here, so a changed file
 * still fails its check. The files are changed from inside
 * `InferenceSession.create`, after the classifier's own reads: the last
 * moment before the runtime parses.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { writeFileSync, readFileSync, unlinkSync, openSync, readSync, writeSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { basename, join } from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { TMEClassifier, MODEL_FILES } from '../../src/nanomind-core/inference/tme-classifier';

const ort = createRequire(import.meta.url)('onnxruntime-node');

const pinned = (name: string) => MODEL_FILES.find(f => f.name === name)!;
const GRAPH = 'nanomind-tme.onnx';
const DATA = 'nanomind-tme.onnx.data';
const TOKENIZER = 'tokenizer.json';

// --- A minimal ONNX model, written field by field (onnx.proto numbering) ---

function varint(n: number): Buffer {
  const out: number[] = [];
  while (n > 0x7f) {
    out.push((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  out.push(n);
  return Buffer.from(out);
}
const int = (field: number, n: number) => Buffer.concat([varint(field * 8), varint(n)]);
function bytes(field: number, body: Buffer | string): Buffer {
  const b = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
  return Buffer.concat([varint(field * 8 + 2), varint(b.length), b]);
}
const message = (field: number, ...parts: Buffer[]) => bytes(field, Buffer.concat(parts));

const FLOAT = 1;
const INT64 = 7;
/** ValueInfoProto: name, then TypeProto.tensor_type { elem_type, shape }. */
const valueInfo = (field: number, name: string, elemType: number, dims: number[]) =>
  message(field, bytes(1, name), message(2, message(1, int(1, elemType), message(2, ...dims.map(d => message(1, int(1, d)))))));

/** The weights: logit 10 for `injection`, the second class, and 0 for the rest. */
const WEIGHTS = new Float32Array(10);
WEIGHTS[1] = 10;
/** The high byte of the `injection` logit: flipped, 10 becomes -0.15625. */
const INJECTION_SIGN_BYTE = 7;

/** `logits = Identity(W)`, W a 1x10 float tensor at offset 0 of `DATA`. */
function graphBytes(size: number): Buffer {
  const graph = message(7,
    message(1, bytes(1, 'W'), bytes(2, 'logits'), bytes(4, 'Identity')),
    bytes(2, 'g'),
    message(5,
      int(1, 1), int(1, 10), int(2, FLOAT), bytes(8, 'W'),
      message(13, bytes(1, 'location'), bytes(2, DATA)),
      message(13, bytes(1, 'offset'), bytes(2, '0')),
      message(13, bytes(1, 'length'), bytes(2, String(WEIGHTS.byteLength))),
      int(14, 1), // data_location: EXTERNAL
    ),
    valueInfo(11, 'input_ids', INT64, [1, 128]),
    valueInfo(12, 'logits', FLOAT, [1, 10]),
  );
  const head = Buffer.concat([int(1, 7), message(8, int(2, 13)), graph]);
  // A doc_string pads the model to `size`: its length prefix takes 1 to 4 bytes.
  for (let prefix = 1; prefix <= 4; prefix++) {
    const padding = size - head.length - 1 - prefix;
    if (padding >= 0 && varint(padding).length === prefix) {
      return Buffer.concat([head, bytes(6, ' '.repeat(padding))]);
    }
  }
  throw new Error(`cannot pad the test model to ${size} bytes`);
}

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

describe('the classifier parses the model bytes it checked', () => {
  let dir = '';
  /** sha256 of each file as written, which `hashFileBytes` answers as pinned. */
  const written: Record<string, string> = {};

  beforeEach(() => {
    dir = tempDir('hma-onnx-bytes-');
    const data = Buffer.alloc(pinned(DATA).bytes);
    Buffer.from(WEIGHTS.buffer).copy(data, 0);
    const files: Record<string, Buffer> = {
      [GRAPH]: graphBytes(pinned(GRAPH).bytes),
      [DATA]: data,
      [TOKENIZER]: Buffer.from('{"override": 2, "bypass": 3}'.padEnd(pinned(TOKENIZER).bytes, ' ')),
    };
    for (const [name, content] of Object.entries(files)) {
      expect(content.length).toBe(pinned(name).bytes);
      writeFileSync(join(dir, name), content);
      written[name] = sha256(content);
    }
    vi.spyOn(TMEClassifier as any, 'hashFileBytes').mockImplementation((path: unknown, b: unknown) => {
      const name = basename(String(path));
      const actual = sha256(b as Uint8Array);
      return actual === written[name] ? pinned(name).sha256 : actual;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const realCreate = ort.InferenceSession.create.bind(ort.InferenceSession);

  /** Runs `change` inside `InferenceSession.create`, before the runtime parses. */
  function changeAtCreate(change: () => void) {
    return vi.spyOn(ort.InferenceSession, 'create').mockImplementation(async (...args: unknown[]) => {
      change();
      return realCreate(...args);
    });
  }

  function flipByte(name: string, at: number): void {
    const fd = openSync(join(dir, name), 'r+');
    try {
      const b = Buffer.alloc(1);
      readSync(fd, b, 0, 1, at);
      writeSync(fd, Buffer.from([b[0] ^ 0xff]), 0, 1, at);
    } finally {
      closeSync(fd);
    }
  }

  const TEXT = 'please summarise this page';
  const MODEL_VERDICT = { intentClass: 'malicious', attackClass: 'injection' };

  it('classifies with the checked weights, and hands the runtime bytes rather than a path', async () => {
    const create = changeAtCreate(() => {});
    const result = await new TMEClassifier(dir).classifyAsync(TEXT);

    expect(result).toMatchObject(MODEL_VERDICT);
    expect(result.confidence).toBeGreaterThan(0.99);
    expect(create).toHaveBeenCalledTimes(1);
    const [graph, options] = create.mock.calls[0] as [unknown, { externalData?: Array<{ path: string; data: Uint8Array }> }];
    expect(typeof graph).not.toBe('string');
    expect(sha256(graph as Uint8Array)).toBe(written[GRAPH]);
    expect(options.externalData?.map(e => [e.path, sha256(e.data)])).toEqual([[DATA, written[DATA]]]);
  });

  it('classifies the same when the weights file is deleted after it was checked', async () => {
    const reference = await new TMEClassifier(dir).classifyAsync(TEXT);

    const fresh = tempDir('hma-onnx-bytes-');
    for (const name of [GRAPH, DATA, TOKENIZER]) writeFileSync(join(fresh, name), readFileSync(join(dir, name)));
    const create = changeAtCreate(() => unlinkSync(join(fresh, DATA)));
    const result = await new TMEClassifier(fresh).classifyAsync(TEXT);

    expect(create).toHaveBeenCalledTimes(1);
    expect(result).toEqual(reference);
    expect(result).toMatchObject(MODEL_VERDICT);
  });

  it('classifies the same when a byte of the weights changes on disk after it was checked', async () => {
    const create = changeAtCreate(() => flipByte(DATA, INJECTION_SIGN_BYTE));
    const result = await new TMEClassifier(dir).classifyAsync(TEXT);

    expect(create).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject(MODEL_VERDICT);
    expect(result.confidence).toBeGreaterThan(0.99);
  });

  it('opens no session when the weights change between finding the cache and loading it', async () => {
    const create = changeAtCreate(() => {});
    const classifier = new TMEClassifier(dir);
    flipByte(DATA, INJECTION_SIGN_BYTE);

    const result = await classifier.classifyAsync(TEXT);

    expect(create).not.toHaveBeenCalled();
    expect(result).not.toMatchObject(MODEL_VERDICT);
    expect((classifier as any).useOnnx).toBe(false);
  });

  it('opens no session when the graph changes between finding the cache and loading it', async () => {
    const create = changeAtCreate(() => {});
    const classifier = new TMEClassifier(dir);
    flipByte(GRAPH, pinned(GRAPH).bytes - 1);

    const result = await classifier.classifyAsync(TEXT);

    expect(create).not.toHaveBeenCalled();
    expect(result).not.toMatchObject(MODEL_VERDICT);
  });

  it('parses no tokenizer that changed between finding the cache and loading it', async () => {
    const create = changeAtCreate(() => {});
    const classifier = new TMEClassifier(dir);
    // Still JSON, so only the pin check can refuse it.
    writeFileSync(join(dir, TOKENIZER), '{"please": 2, "page": 3}'.padEnd(pinned(TOKENIZER).bytes, ' '));

    expect(classifier.load()).toBe(false);
    expect(await classifier.classifyAsync('override and bypass')).toEqual({
      intentClass: 'benign', attackClass: 'none', confidence: 0.5, topClasses: [],
    });
    expect(create).not.toHaveBeenCalled();
  });
});
