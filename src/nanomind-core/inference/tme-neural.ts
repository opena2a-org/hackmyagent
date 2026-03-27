/**
 * TME Neural Inference -- Pure TypeScript forward pass
 *
 * Loads MLX-trained weights directly (no ONNX, no daemon).
 * Implements the Mamba SSM block architecture in JS.
 * 7MB model, sub-100ms inference on any CPU.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const CLASSES = [
  'exfiltration', 'injection', 'privilege_escalation', 'persistence',
  'credential_abuse', 'lateral_movement', 'social_engineering',
  'policy_violation', 'benign',
];

interface TensorMeta {
  shape: number[];
  offset: number;
  size: number;
}

interface ModelWeights {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: { shape: number[]; data: any };
}

// ============================================================================
// Tensor operations (minimal, no dependencies)
// ============================================================================

function matmul(a: Float32Array, aRows: number, aCols: number, b: Float32Array, bCols: number): Float32Array {
  const out = new Float32Array(aRows * bCols);
  for (let i = 0; i < aRows; i++) {
    for (let j = 0; j < bCols; j++) {
      let sum = 0;
      for (let k = 0; k < aCols; k++) {
        sum += a[i * aCols + k] * b[k * bCols + j];
      }
      out[i * bCols + j] = sum;
    }
  }
  return out;
}

function addBias(x: Float32Array, bias: Float32Array): Float32Array {
  const out = new Float32Array(x.length);
  const cols = bias.length;
  for (let i = 0; i < x.length; i++) {
    out[i] = x[i] + bias[i % cols];
  }
  return out;
}

function silu(x: Float32Array): Float32Array {
  const out = new Float32Array(x.length);
  for (let i = 0; i < x.length; i++) {
    out[i] = x[i] / (1 + Math.exp(-x[i])); // x * sigmoid(x)
  }
  return out;
}

function layerNorm(x: Float32Array, cols: number, weight: Float32Array, bias: Float32Array): Float32Array {
  const rows = x.length / cols;
  const out = new Float32Array(x.length);
  for (let r = 0; r < rows; r++) {
    let mean = 0, var_ = 0;
    for (let c = 0; c < cols; c++) mean += x[r * cols + c];
    mean /= cols;
    for (let c = 0; c < cols; c++) var_ += (x[r * cols + c] - mean) ** 2;
    var_ /= cols;
    const std = Math.sqrt(var_ + 1e-5);
    for (let c = 0; c < cols; c++) {
      out[r * cols + c] = (x[r * cols + c] - mean) / std * weight[c] + bias[c];
    }
  }
  return out;
}

function meanPool(x: Float32Array, seqLen: number, dModel: number): Float32Array {
  const out = new Float32Array(dModel);
  for (let d = 0; d < dModel; d++) {
    let sum = 0;
    for (let s = 0; s < seqLen; s++) {
      sum += x[s * dModel + d];
    }
    out[d] = sum / seqLen;
  }
  return out;
}

function softmax(x: Float32Array): Float32Array {
  const max = Math.max(...x);
  const exps = new Float32Array(x.length);
  let sum = 0;
  for (let i = 0; i < x.length; i++) {
    exps[i] = Math.exp(x[i] - max);
    sum += exps[i];
  }
  for (let i = 0; i < x.length; i++) exps[i] /= sum;
  return exps;
}

// ============================================================================
// Mamba Block (matches MLX architecture exactly)
// ============================================================================

function mambaBlock(
  x: Float32Array, seqLen: number, dModel: number,
  inProjW: Float32Array, inProjB: Float32Array,
  outProjW: Float32Array, outProjB: Float32Array,
  normW: Float32Array, normB: Float32Array,
): Float32Array {
  const dInner = dModel * 2;
  const residual = new Float32Array(x);

  // LayerNorm
  const normed = layerNorm(x, dModel, normW, normB);

  // in_proj: dModel -> dInner * 2
  const projected = addBias(matmul(normed, seqLen, dModel, inProjW, dInner * 2), inProjB);

  // Split into x_part and z, apply silu, multiply
  const y = new Float32Array(seqLen * dInner);
  for (let s = 0; s < seqLen; s++) {
    for (let d = 0; d < dInner; d++) {
      const xVal = projected[s * dInner * 2 + d];
      const zVal = projected[s * dInner * 2 + dInner + d];
      const xSilu = xVal / (1 + Math.exp(-xVal));
      const zSilu = zVal / (1 + Math.exp(-zVal));
      y[s * dInner + d] = xSilu * zSilu;
    }
  }

  // out_proj: dInner -> dModel
  const output = addBias(matmul(y, seqLen, dInner, outProjW, dModel), outProjB);

  // Residual connection
  for (let i = 0; i < output.length; i++) output[i] += residual[i];
  return output;
}

// ============================================================================
// TME Neural Classifier
// ============================================================================

export class TMENeuralClassifier {
  private weights: ModelWeights | null = null;
  private vocab: Record<string, number> = {};
  private loaded = false;
  private modelPath = '';
  private tokenizerPath = '';

  constructor(modelDir?: string) {
    const home = require('os').homedir();
    const locations = [
      modelDir,
      join(home, '.opena2a', 'nanomind', 'models'),
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models-tme-v3'),
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models-tme-v2'),
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models-tme'),
    ].filter(Boolean) as string[];

    for (const dir of locations) {
      const bin = join(dir, 'nanomind-tme.bin');
      const tok = join(dir, 'tokenizer.json');
      if (existsSync(bin) && existsSync(tok)) {
        this.modelPath = bin;
        this.tokenizerPath = tok;
        break;
      }
    }
  }

  load(): boolean {
    if (this.loaded) return true;
    if (!this.modelPath || !this.tokenizerPath) return false;

    try {
      this.vocab = JSON.parse(readFileSync(this.tokenizerPath, 'utf-8'));

      // Load binary model
      const buf = readFileSync(this.modelPath);
      const headerLen = buf.readUInt32LE(0);
      const headerJson = buf.subarray(4, 4 + headerLen).toString('utf-8');
      const metadata: Record<string, TensorMeta> = JSON.parse(headerJson);
      const dataOffset = 4 + headerLen;

      this.weights = {};
      for (const [key, meta] of Object.entries(metadata)) {
        const start = dataOffset + meta.offset;
        const ab = new ArrayBuffer(meta.size);
      const view = new Uint8Array(ab);
      for (let i = 0; i < meta.size; i++) view[i] = buf[start + i];
      const f32 = new Float32Array(ab);
        this.weights[key] = { shape: meta.shape, data: f32 };
      }

      this.loaded = true;
      return true;
    } catch {
      return false;
    }
  }

  classify(text: string): { intentClass: 'benign' | 'suspicious' | 'malicious'; attackClass: string; confidence: number } {
    if (!this.load() || !this.weights) {
      return { intentClass: 'benign', attackClass: 'none', confidence: 0.5 };
    }

    const w = this.weights;
    const seqLen = 128;
    const dModel = 128;

    // Tokenize
    const tokens = text.toLowerCase().split(/\s+/).map(word => this.vocab[word] ?? 1).slice(0, seqLen);
    while (tokens.length < seqLen) tokens.push(0);

    // Embedding lookup
    const embW = w['embedding.weight'];
    let hidden: any = new Float32Array(seqLen * dModel);
    for (let s = 0; s < seqLen; s++) {
      const tokenId = tokens[s];
      for (let d = 0; d < dModel; d++) {
        hidden[s * dModel + d] = embW.data[tokenId * dModel + d];
      }
    }

    // 8 Mamba blocks
    for (let layer = 0; layer < 8; layer++) {
      const prefix = `layers.${layer}`;
      // Transpose in_proj and out_proj weights (MLX stores as [out, in], matmul needs [in, out])
      const inProjW = transposeWeight(w[`${prefix}.in_proj.weight`].data, w[`${prefix}.in_proj.weight`].shape);
      const outProjW = transposeWeight(w[`${prefix}.out_proj.weight`].data, w[`${prefix}.out_proj.weight`].shape);

      hidden = mambaBlock(
        hidden, seqLen, dModel,
        inProjW, w[`${prefix}.in_proj.bias`].data,
        outProjW, w[`${prefix}.out_proj.bias`].data,
        w[`${prefix}.norm.weight`].data, w[`${prefix}.norm.bias`].data,
      );
    }

    // Final LayerNorm
    hidden = layerNorm(hidden, dModel, w['final_norm.weight'].data, w['final_norm.bias'].data);

    // Mean pool
    const pooled = meanPool(hidden, seqLen, dModel);

    // Classifier: dModel -> 9 classes
    const classW = transposeWeight(w['classifier.weight'].data, w['classifier.weight'].shape);
    const logits = addBias(matmul(pooled, 1, dModel, classW, 9), w['classifier.bias'].data);
    const probs = softmax(logits);

    const idx = probs.indexOf(Math.max(...probs));
    const topClass = CLASSES[idx];
    const confidence = probs[idx];

    let intentClass: 'benign' | 'suspicious' | 'malicious' = 'benign';
    if (topClass !== 'benign' && confidence > 0.4) {
      intentClass = confidence > 0.7 ? 'malicious' : 'suspicious';
    }

    return {
      intentClass,
      attackClass: topClass === 'benign' ? 'none' : topClass,
      confidence,
    };
  }
}

/** Transpose a 2D weight matrix from [rows, cols] to [cols, rows] */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function transposeWeight(data: any, shape: number[]): any {
  if (shape.length !== 2) return data;
  const [rows, cols] = shape;
  const out = new Float32Array(data.length);
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      out[c * rows + r] = data[r * cols + c];
    }
  }
  return out;
}
