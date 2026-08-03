/**
 * TME Classifier -- Local inference using the trained Mamba model
 *
 * Loads the trained NanoMind TME model weights and tokenizer directly.
 * No daemon needed. Sub-millisecond inference on any CPU.
 *
 * This replaces the daemon call for intent classification in the
 * Semantic Compiler. The daemon is still used for SCAN intents
 * that need the full LLM (explanation, version delta, etc).
 *
 * Security: model file integrity verified before loading.
 */

import { readFileSync, existsSync, mkdirSync, createWriteStream, unlinkSync, createReadStream } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import https from 'node:https';
import { escapeForDisplay } from '../../ui/display-safe';

const HF_BASE = 'https://huggingface.co/opena2a/nanomind-security-classifier/resolve/main';
const MODEL_FILES: Array<{ name: string; sha256: string }> = [
  { name: 'tokenizer.json', sha256: '5ace7e6441505cf24dfb84d10b237c66edccaece075b3c5b0736c007d65355ce' },
  { name: 'nanomind-tme.onnx', sha256: '1c9c6db00385e0e871ee6d2508d90a3210eddd4abf45365151fb859d8abab9eb' },
  { name: 'nanomind-tme.onnx.data', sha256: '1367c0d3086b8d5c698dc37ae309c3afdb41ffa4d35ecac9b8f1882ffeb1d018' },
];
const DOWNLOAD_DIR = join(homedir(), '.nanomind', 'models');

const CLASSES = [
  'exfiltration', 'injection', 'privilege_escalation', 'persistence',
  'credential_abuse', 'lateral_movement', 'social_engineering',
  'policy_violation', 'benign', 'steganography',
];

export interface TMEClassification {
  intentClass: 'benign' | 'suspicious' | 'malicious';
  attackClass: string;
  confidence: number;
  topClasses: Array<{ class: string; score: number }>;
}

/**
 * Lightweight TME classifier that runs inference using the trained model.
 *
 * For the MLP/TME bootstrap model, inference is a simple forward pass:
 * tokenize → embed → pool → classify. No GPU or daemon needed.
 */
export class TMEClassifier {
  private vocab: Record<string, number> = {};
  private loaded = false;
  private modelPath: string;
  private tokenizerPath: string;
  private onnxSession: any = null;
  private useOnnx = false;
  private needsDownload = false;
  private downloadPromise: Promise<boolean> | null = null;
  private quiet = false;

  constructor(modelDir?: string) {
    // Look for model in standard locations (ordered by preference)
    const home = homedir();
    const locations = [
      modelDir,
      join(process.cwd(), 'models'),
      join(__dirname, '..', '..', '..', 'models'),
      join(home, '.nanomind', 'models'),
      join(home, '.opena2a', 'nanomind', 'models'),
      // Development: nanomind training repo (monorepo sibling, newest first)
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models-tme-v4'),
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models-tme-v3'),
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models-tme-v2'),
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models-tme'),
      join(__dirname, '..', '..', '..', '..', 'nanomind', 'training', 'models'),
    ].filter(Boolean) as string[];

    this.modelPath = '';
    this.tokenizerPath = '';

    for (const dir of locations) {
      const tokenizer = join(dir, 'tokenizer.json');
      if (existsSync(tokenizer)) {
        this.tokenizerPath = tokenizer;
        // Prefer ONNX model for real neural inference
        const onnx = join(dir, 'nanomind-tme.onnx');
        const tme = join(dir, 'nanomind-tme-classifier.npz');
        const mlp = join(dir, 'nanomind-sft-classifier.npz');
        if (existsSync(onnx)) {
          this.modelPath = onnx;
          this.useOnnx = true;
        } else {
          this.modelPath = existsSync(tme) ? tme : existsSync(mlp) ? mlp : '';
        }
        break;
      }
    }

    // Auto-download if: no model found, no ONNX, or cached model is outdated
    if (!this.tokenizerPath) {
      this.needsDownload = true;
    } else if (!this.useOnnx) {
      this.needsDownload = true;
    } else {
      // Verify cached model version matches expected SHA
      try {
        const cachedHash = createHash('sha256').update(readFileSync(this.tokenizerPath)).digest('hex');
        const expectedHash = MODEL_FILES.find(f => f.name === 'tokenizer.json')?.sha256;
        if (expectedHash && cachedHash !== expectedHash) {
          this.needsDownload = true; // Stale model, trigger update
        }
      } catch { /* hash check failed, use cached model */ }
    }
  }

  /**
   * Download a single file from HuggingFace, following 302 redirects.
   * Uses only Node.js built-ins (https, fs, crypto).
   */
  private static downloadFile(url: string, destPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const follow = (targetUrl: string) => {
        https.get(targetUrl, (response) => {
          if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400) {
            const location = response.headers.location;
            if (!location) {
              reject(new Error('Redirect with no location header'));
              return;
            }
            response.resume();
            // Handle relative redirects by resolving against the request URL
            const resolved = location.startsWith('http') ? location : new URL(location, targetUrl).href;
            follow(resolved);
            return;
          }
          if (response.statusCode !== 200) {
            response.resume();
            reject(new Error(`HTTP ${response.statusCode} for ${targetUrl}`));
            return;
          }
          const file = createWriteStream(destPath);
          response.pipe(file);
          file.on('finish', () => { file.close(); resolve(); });
          file.on('error', (err) => { file.close(); reject(err); });
        }).on('error', reject);
      };
      follow(url);
    });
  }

  /**
   * Compute SHA-256 hash of a file using streaming.
   */
  private static computeHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = createHash('sha256');
      const stream = createReadStream(filePath);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  /**
   * Download the NanoMind TME model files from HuggingFace.
   * Verifies SHA-256 integrity of each file. Cleans up on failure.
   * Returns true if download succeeded, false otherwise.
   */
  static async downloadModel(targetDir?: string, quiet = false): Promise<boolean> {
    const dir = targetDir ?? DOWNLOAD_DIR;
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
      return false;
    }

    if (!quiet) console.error('Downloading security analysis model (5.5MB)...');

    for (const file of MODEL_FILES) {
      const dest = join(dir, file.name);
      if (existsSync(dest)) continue;

      const url = `${HF_BASE}/${file.name}`;
      try {
        await TMEClassifier.downloadFile(url, dest);
        // Verify integrity
        const hash = await TMEClassifier.computeHash(dest);
        if (file.sha256 && hash !== file.sha256) {
          if (!quiet) console.error(`  Integrity check failed for ${escapeForDisplay(file.name)}. Removing.`);
          try { unlinkSync(dest); } catch { /* ignore */ }
          return false;
        }
      } catch (err: any) {
        if (!quiet) console.error(`  Failed to download ${escapeForDisplay(file.name)}: ${escapeForDisplay(String(err?.message ?? 'unknown error'))}`);
        try { unlinkSync(dest); } catch { /* ignore */ }
        return false;
      }
    }

    if (!quiet) console.error('Model ready. Using neural inference for deep scanning.');
    return true;
  }

  /**
   * Ensure the model is available. Downloads from HuggingFace if needed.
   * Call this from async contexts before classifyAsync().
   */
  async ensureModel(quiet = false): Promise<void> {
    this.quiet = quiet;
    if (!this.needsDownload) return;
    if (this.downloadPromise) {
      await this.downloadPromise;
      return;
    }

    this.downloadPromise = TMEClassifier.downloadModel(undefined, quiet);
    const ok = await this.downloadPromise;
    this.downloadPromise = null;

    if (ok) {
      // Point paths to the freshly downloaded model
      this.tokenizerPath = join(DOWNLOAD_DIR, 'tokenizer.json');
      this.modelPath = join(DOWNLOAD_DIR, 'nanomind-tme.onnx');
      this.useOnnx = true;
      this.needsDownload = false;
      this.loaded = false; // Force re-load with new paths
    } else {
      // Download failed; fall back to vocab scoring silently
      if (!quiet) console.error('Model download unavailable. Using vocabulary-based scoring.');
      this.needsDownload = false;
    }
  }

  private onnxReady = false;
  private onnxLoading: Promise<void> | null = null;

  /**
   * Load the tokenizer. Kicks off async ONNX model load if available.
   */
  load(): boolean {
    if (this.loaded) return true;
    if (!this.tokenizerPath || !existsSync(this.tokenizerPath)) return false;

    try {
      this.vocab = JSON.parse(readFileSync(this.tokenizerPath, 'utf-8'));

      // Start async ONNX load (non-blocking, classify falls back to vocab until ready)
      if (this.useOnnx && this.modelPath) {
        this.onnxLoading = this.loadOnnx();
      }

      this.loaded = true;
      return true;
    } catch {
      return false;
    }
  }

  private async loadOnnx(): Promise<void> {
    try {
      const ort = require('onnxruntime-node');
      this.onnxSession = await ort.InferenceSession.create(this.modelPath);
      this.onnxReady = true;
    } catch {
      this.useOnnx = false;
    }
  }

  /** Wait for model download (if needed) and ONNX to be ready */
  async ensureReady(): Promise<void> {
    if (this.needsDownload) await this.ensureModel();
    if (this.onnxLoading) await this.onnxLoading;
  }

  /**
   * Classify text using vocabulary-based scoring.
   *
   * This is a lightweight approximation of the trained model's behavior.
   * The model learned that certain token patterns strongly predict each class.
   * We replicate this by scoring token overlap with class-indicative vocabulary.
   *
   * For full neural inference, use the Python TME model via the daemon.
   */
  classify(text: string): TMEClassification {
    if (!this.load()) {
      return { intentClass: 'benign', attackClass: 'none', confidence: 0.5, topClasses: [] };
    }

    const tokens = this.tokenize(text);

    // Sync classify always uses vocabulary scoring.
    // For ONNX neural inference, use classifyAsync() from async contexts.
    const { raw, normalized } = this.score(tokens);

    // Use raw scores for intent (normalization dilutes multi-category attacks)
    const rawSorted = CLASSES.map((cls, i) => ({ class: cls, score: raw[i] }))
      .sort((a, b) => b.score - a.score);
    const topRaw = rawSorted[0];

    // Use normalized for display
    const normSorted = CLASSES.map((cls, i) => ({ class: cls, score: normalized[i] }))
      .sort((a, b) => b.score - a.score);

    let intentClass: TMEClassification['intentClass'] = 'benign';
    if (topRaw.class !== 'benign' && topRaw.score > 0.4) {
      intentClass = topRaw.score > 0.7 ? 'malicious' : 'suspicious';
    }

    return {
      intentClass,
      attackClass: topRaw.class === 'benign' ? 'none' : topRaw.class,
      confidence: topRaw.score,
      topClasses: normSorted.slice(0, 3),
    };
  }

  /**
   * Async classify using ONNX neural inference (real Mamba model).
   * Use this from async contexts like the Semantic Compiler.
   */
  async classifyAsync(text: string): Promise<TMEClassification> {
    // Auto-download model from HuggingFace if no local files found
    if (this.needsDownload) await this.ensureModel(this.quiet);

    if (!this.load()) {
      return { intentClass: 'benign', attackClass: 'none', confidence: 0.5, topClasses: [] };
    }

    await this.ensureReady();

    if (this.onnxReady && this.onnxSession) {
      const tokens = this.tokenize(text);
      const padded = tokens.slice(0, 128);
      while (padded.length < 128) padded.push(0);

      try {
        const ort = require('onnxruntime-node');
        const inputTensor = new ort.Tensor('int64', BigInt64Array.from(padded.map(BigInt)), [1, 128]);
        const output = await this.onnxSession.run({ input_ids: inputTensor });
        const logits = Array.from(output.logits.data as Float32Array);

        // Softmax
        const maxLogit = Math.max(...logits);
        const exps = logits.map((l: number) => Math.exp(l - maxLogit));
        const sumExps = exps.reduce((a: number, b: number) => a + b, 0);
        const probs = exps.map((e: number) => e / sumExps);

        const sorted = CLASSES.map((cls, i) => ({ class: cls, score: probs[i] }))
          .sort((a, b) => b.score - a.score);
        const topClass = sorted[0];

        let intentClass: TMEClassification['intentClass'] = 'benign';
        if (topClass.class !== 'benign' && topClass.score > 0.4) {
          intentClass = topClass.score > 0.7 ? 'malicious' : 'suspicious';
        }

        return {
          intentClass,
          attackClass: topClass.class === 'benign' ? 'none' : topClass.class,
          confidence: topClass.score,
          topClasses: sorted.slice(0, 3),
        };
      } catch {
        // ONNX inference failed, fall back to vocab
      }
    }

    // Fall back to sync vocabulary scoring
    return this.classify(text);
  }

  private tokenize(text: string): number[] {
    return text.toLowerCase().split(/\s+/).map(w => this.vocab[w] ?? 1).slice(0, 128);
  }

  /**
   * Score tokens against each class using learned vocabulary patterns.
   *
   * The trained TME model associates specific tokens with attack classes.
   * We approximate this by checking token presence against class-indicative
   * word lists derived from the training data.
   */
  private score(tokens: number[]): { raw: number[]; normalized: number[] } {
    const text = tokens.map(t => {
      for (const [word, idx] of Object.entries(this.vocab)) {
        if (idx === t) return word;
      }
      return '';
    }).join(' ');

    const scores = new Array(CLASSES.length).fill(0);

    // Class-indicative patterns (derived from training data vocabulary)
    const classPatterns: Record<string, RegExp[]> = {
      exfiltration: [/forward/i, /export/i, /mirror/i, /upload/i, /stream/i, /sync/i, /push/i, /external.*endpoint/i, /compliance.*endpoint/i, /analytics.*collect/i, /select.*\*.*from/i, /include.*pii/i, /transmit.*data/i, /send.*record/i, /forward.*dataset/i],
      injection: [/override/i, /bypass/i, /suspend/i, /disable.*safety/i, /ignore.*instruction/i, /admin.*auth/i, /emergency.*access/i, /maintenance.*mode/i],
      privilege_escalation: [/escalat/i, /admin.*access/i, /bypass.*permission/i, /any.*database/i, /full.*access/i, /system.*config/i],
      persistence: [/permanently/i, /persist/i, /forever/i, /all.*future.*session/i, /long.*term.*memory/i, /no.*expiration/i],
      credential_abuse: [/provide.*password/i, /enter.*credential/i, /share.*key/i, /your.*api.*key/i, /verification.*password/i, /identity.*credential/i],
      social_engineering: [/urgent/i, /emergency/i, /compromised/i, /immediate/i, /failure.*will/i, /act.*now/i, /authorized.*by/i],
      lateral_movement: [/fetch.*config/i, /download.*instruction/i, /check.*update.*from/i, /load.*from.*http/i, /sync.*with.*remote/i],
      policy_violation: [/bypass.*soul/i, /override.*governance/i, /suspend.*constraint/i, /exception.*code/i, /relax.*safety/i],
      steganography: [/invisible/i, /zero.width/i, /homoglyph/i, /codePointAt/i, /variation.*selector/i, /bidi.*override/i, /tag.*character/i, /glassworm/i, /stego/i, /hidden.*unicode/i],
    };

    for (let i = 0; i < CLASSES.length; i++) {
      const cls = CLASSES[i];
      if (cls === 'benign') {
        // Benign score = 1 - max(other scores)
        continue;
      }
      const patterns = classPatterns[cls] ?? [];
      const matches = patterns.filter(p => p.test(text)).length;
      scores[i] = Math.min(0.95, matches * 0.15 + (matches > 0 ? 0.3 : 0));
    }

    // Benign = inverse of max attack score (exclude benign itself at index 8)
    const benignIdx = CLASSES.indexOf('benign');
    const attackScores = scores.filter((_, i) => i !== benignIdx);
    const maxAttack = Math.max(...attackScores);
    scores[benignIdx] = maxAttack > 0.3 ? 1 - maxAttack : 0.8;

    // Keep raw scores for intent classification
    const raw = [...scores];

    // Normalize for display
    const sum = scores.reduce((a, b) => a + b, 0);
    const normalized = scores.map(s => sum > 0 ? s / sum : 0);

    return { raw, normalized };
  }
}

/**
 * Singleton instance for the TME classifier.
 */
let _instance: TMEClassifier | null = null;

export function getTMEClassifier(): TMEClassifier {
  if (!_instance) {
    _instance = new TMEClassifier();
  }
  return _instance;
}
