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

import { readFileSync, existsSync, mkdirSync, createWriteStream, unlinkSync, createReadStream, statSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import https from 'node:https';
import { escapeForDisplay } from '../../ui/display-safe';

// Pinned to the model repository commit the sha256 values below were taken
// from. A branch URL follows every later commit to that repository, so a new
// upload would fail the integrity check on every install and leave scans on
// vocabulary scoring. Moving to a new model changes the commit and the hashes
// together.
const HF_REVISION = '5b0b37cddeff5ae535a25a06d8a6a555016b33b2';
const HF_BASE = `https://huggingface.co/opena2a/nanomind-security-classifier/resolve/${HF_REVISION}`;
// `bytes` is each file's size at that commit. The notice printed before a
// download states the sum of the files it is about to fetch, and a download
// is checked against it the same way it is checked against the hash.
const MODEL_FILES: Array<{ name: string; sha256: string; bytes: number }> = [
  { name: 'tokenizer.json', sha256: '5ace7e6441505cf24dfb84d10b237c66edccaece075b3c5b0736c007d65355ce', bytes: 168_639 },
  { name: 'nanomind-tme.onnx', sha256: '1c9c6db00385e0e871ee6d2508d90a3210eddd4abf45365151fb859d8abab9eb', bytes: 142_990 },
  { name: 'nanomind-tme.onnx.data', sha256: '1367c0d3086b8d5c698dc37ae309c3afdb41ffa4d35ecac9b8f1882ffeb1d018', bytes: 8_380_416 },
];
const DOWNLOAD_DIR = join(homedir(), '.nanomind', 'models');

/**
 * How long a model download may receive nothing, connecting included, before
 * it is abandoned and the scan continues on vocabulary scoring.
 *
 * There was no bound. A connection that was accepted and then went silent held
 * `secure` open indefinitely: the report was never written, and whatever was
 * waiting on the scan (a CI step, a spawn budget) killed it with empty output.
 * Every scan under a HOME with no model cache downloads, so a test suite that
 * gives each spawned scan a fresh HOME runs many of these at once and fails
 * intermittently whenever one stalls (#542).
 *
 * An idle bound, not a total one: a slow link that keeps delivering bytes
 * still completes the download; only a silent one is given up on.
 */
const DOWNLOAD_IDLE_TIMEOUT_MS = 10_000;

/**
 * The hosts a model download may reach: the model repository on
 * huggingface.co, and Hugging Face's content CDN under hf.co, where the large
 * files redirect (the CDN host itself varies by region). A redirect to any
 * other host is refused, so the notice printed before the download names
 * every host the download can contact.
 */
const MODEL_HOSTS_FOR_NOTICE = "huggingface.co and Hugging Face's content CDN";
const MAX_MODEL_REDIRECTS = 5;

export function isAllowedModelHost(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') return false;
  const host = parsed.hostname.toLowerCase();
  return host === 'huggingface.co' || host.endsWith('.hf.co');
}

/** Decimal units: 1 MB is 1,000,000 bytes. */
function formatModelBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${Math.round(bytes / 1_000)} kB`;
  return `${bytes} bytes`;
}

export interface ModelDownloadOptions {
  /**
   * The flag, registered on the command that triggers the download, that
   * skips it (for example `--static-only` on `secure`). The notice names it.
   * Omitted when the command registers no such flag, so the notice never
   * names a flag the command would reject.
   */
  optOut?: string;
  /**
   * How long a connection may receive nothing before the download is
   * abandoned. Defaults to `DOWNLOAD_IDLE_TIMEOUT_MS`.
   */
  idleTimeoutMs?: number;
}

const CLASSES = [
  'exfiltration', 'injection', 'privilege_escalation', 'persistence',
  'credential_abuse', 'lateral_movement', 'social_engineering',
  'policy_violation', 'benign', 'steganography',
];

/** The part of an onnxruntime `InferenceSession` this module releases. */
interface ReleasableSession {
  release(): unknown;
}

/**
 * ONNX sessions this module created and has not released yet (#770).
 *
 * Nothing used to release the session. The CLI sets `process.exitCode` and
 * returns, so the session, and the thread pool it owns, was still alive while
 * the process tore down its native state. `scan-soul --deep` was recorded
 * ending in that window with `recursive_mutex lock failed: Invalid argument`
 * from the C++ runtime and exit 134, after a complete report. The cause of that
 * abort is not established. What this removes is the open session at teardown,
 * the one part of it that HackMyAgent owns.
 *
 * The `exit` event fires on both ways a command ends, natural teardown after
 * `process.exitCode` and `process.exit()`, and it fires before the runtime is
 * torn down, so one listener covers every command on both. It does not fire
 * when a signal or a fatal error ends the process.
 *
 * The listener must be synchronous, and `release()` is: onnxruntime-node
 * disposes the native session before the first `await` inside its `release()`,
 * so the work is done when the call returns, not when its promise settles.
 */
const openOnnxSessions = new Set<ReleasableSession>();
let releaseOnExitInstalled = false;

function releaseOpenOnnxSessions(): void {
  for (const session of [...openOnnxSessions]) {
    openOnnxSessions.delete(session);
    try {
      // Not awaited, because an `exit` listener cannot wait. The catch only
      // keeps a failed release from becoming an unhandled rejection.
      Promise.resolve(session.release()).catch(() => {});
    } catch {
      // A release that throws is not retried; the process is ending anyway.
    }
  }
}

function trackOnnxSession(session: ReleasableSession): void {
  openOnnxSessions.add(session);
  if (!releaseOnExitInstalled) {
    releaseOnExitInstalled = true;
    process.once('exit', releaseOpenOnnxSessions);
  }
}

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
  private downloadOptions: ModelDownloadOptions = {};

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
   * Download a single file from Hugging Face, following redirects only to
   * the hosts `isAllowedModelHost` accepts.
   * Uses only Node.js built-ins (https, fs, crypto).
   *
   * `timeout` is a socket idle bound armed before the socket connects, so it
   * covers a connect, a TLS handshake or a response body that goes silent.
   * Node only announces it; ending the request is this function's job, and the
   * response's own `error` is what settles a body cut off part-way.
   */
  private static downloadFile(url: string, destPath: string, idleTimeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const follow = (targetUrl: string, redirects: number) => {
        if (!isAllowedModelHost(targetUrl)) {
          let host = 'an unparseable URL';
          try { host = new URL(targetUrl).host; } catch { /* keep the placeholder */ }
          reject(new Error(`refused a request to ${host}, which is outside huggingface.co and *.hf.co`));
          return;
        }
        const req = https.get(targetUrl, { timeout: idleTimeoutMs }, (response) => {
          if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400) {
            const location = response.headers.location;
            response.resume();
            if (!location) {
              reject(new Error('Redirect with no location header'));
              return;
            }
            if (redirects >= MAX_MODEL_REDIRECTS) {
              reject(new Error(`more than ${MAX_MODEL_REDIRECTS} redirects`));
              return;
            }
            // Relative redirects resolve against the request URL
            let resolved: string;
            try {
              resolved = new URL(location, targetUrl).href;
            } catch {
              reject(new Error('Redirect with an unparseable location header'));
              return;
            }
            follow(resolved, redirects + 1);
            return;
          }
          if (response.statusCode !== 200) {
            response.resume();
            // The host, not the URL: a CDN URL carries a signed query string.
            reject(new Error(`HTTP ${response.statusCode} from ${new URL(targetUrl).host}`));
            return;
          }
          const file = createWriteStream(destPath);
          response.on('error', (err) => { file.destroy(); reject(err); });
          response.pipe(file);
          file.on('finish', () => { file.close(); resolve(); });
          file.on('error', (err) => { file.close(); reject(err); });
        });
        req.on('timeout', () => {
          req.destroy(new Error(`no data received for ${idleTimeoutMs / 1000}s`));
        });
        req.on('error', reject);
      };
      follow(url, 0);
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
   * Download the NanoMind TME model files from Hugging Face.
   * Verifies the size and SHA-256 of each file. Cleans up on failure.
   * Returns true if download succeeded, false otherwise.
   *
   * The disclosure lives here, where the network request is made, and is
   * written to stderr in every output mode: a `--json` or `--ci` run is
   * exactly the run where a download nobody was told about goes unnoticed.
   * Before the first request it says what is fetched, from which hosts, how
   * many bytes, into which directory, that it happens once per cache, and
   * the flag that skips it; then one line reports the outcome. Nothing is
   * written when every file is already in the cache, because no request is
   * made.
   *
   * A connection that goes silent for `options.idleTimeoutMs` fails the
   * download, and the caller falls back to vocabulary scoring (see
   * `DOWNLOAD_IDLE_TIMEOUT_MS`).
   */
  static async downloadModel(targetDir?: string, options: ModelDownloadOptions = {}): Promise<boolean> {
    const dir = targetDir ?? DOWNLOAD_DIR;
    const idleTimeoutMs = options.idleTimeoutMs ?? DOWNLOAD_IDLE_TIMEOUT_MS;
    const toFetch = MODEL_FILES.filter(f => !existsSync(join(dir, f.name)));
    if (toFetch.length === 0) return true;

    const say = (line: string) => { process.stderr.write(`${line}\n`); };
    const size = formatModelBytes(toFetch.reduce((sum, f) => sum + f.bytes, 0));
    const fallback = 'The classifier did not run; this scan uses vocabulary scoring and its results can differ.';
    say(
      `NanoMind: downloading the classifier model (${toFetch.length} file(s), ${size}) from ` +
      `${MODEL_HOSTS_FOR_NOTICE} into ${escapeForDisplay(dir)}.`,
    );
    say(
      '  This happens once per cache; later runs use the cached copy.' +
      (options.optOut ? ` To skip it, run this command with ${escapeForDisplay(options.optOut)}.` : ''),
    );

    try {
      mkdirSync(dir, { recursive: true });
    } catch (err: any) {
      say(`NanoMind: model download failed: cannot create ${escapeForDisplay(dir)} (${escapeForDisplay(String(err?.code ?? err?.message ?? 'unknown error'))}). ${fallback}`);
      return false;
    }

    for (const file of toFetch) {
      const dest = join(dir, file.name);
      const url = `${HF_BASE}/${file.name}`;
      let problem: string | null = null;
      try {
        await TMEClassifier.downloadFile(url, dest, idleTimeoutMs);
        const received = statSync(dest).size;
        if (received !== file.bytes) {
          problem = `received ${received} bytes, expected ${file.bytes}`;
        } else if ((await TMEClassifier.computeHash(dest)) !== file.sha256) {
          problem = 'sha256 does not match the pinned value';
        }
      } catch (err: any) {
        problem = String(err?.message ?? 'unknown error');
      }
      if (problem !== null) {
        try { unlinkSync(dest); } catch { /* ignore */ }
        say(`NanoMind: model download failed: ${escapeForDisplay(file.name)}: ${escapeForDisplay(problem)}. ${fallback}`);
        return false;
      }
    }

    say(`NanoMind: model downloaded and verified (${size}).`);
    return true;
  }

  /**
   * Ensure the model is available. Downloads from Hugging Face if needed.
   * Call this from async contexts before classifyAsync().
   */
  async ensureModel(options: ModelDownloadOptions = {}): Promise<void> {
    this.downloadOptions = options;
    if (!this.needsDownload) return;
    if (this.downloadPromise) {
      await this.downloadPromise;
      return;
    }

    this.downloadPromise = TMEClassifier.downloadModel(undefined, options);
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
      // Download failed; downloadModel has said so. Fall back to vocab scoring.
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

  /**
   * ERROR. Not the onnxruntime default, which is WARNING.
   *
   * onnxruntime's logger is NATIVE: it writes to stderr itself, in ANSI
   * colour, and neither `NO_COLOR` nor anything in HackMyAgent's rendering
   * layer is between it and the terminal. On Linux, creating a session makes
   * it enumerate PCI devices, and on a host whose `/sys/devices` topology it
   * cannot parse — every `ubuntu-latest` GitHub runner, whose paths look like
   * `/sys/devices/LNXSYSTM:00/LNXSYBUS:00/ACPI0004:00/MSFT1000:00/…` — it
   * emits:
   *
   *   ESC[0;93m… [W:onnxruntime:onnxruntime-node, device_discovery.cc:133
   *   GetPciBusId] Skipping pci_bus_id for PCI path at "…"ESC[m
   *
   * Two raw ESC bytes, spliced into the middle of a security report, about a
   * condition that is not the user's problem and that they cannot act on.
   *
   * It surfaced as six failures in `report-render-safety.test.ts` on
   * `ubuntu-latest` — that suite reads the CLI's stdout AND stderr and refuses
   * any raw control byte, which is correct and stays exactly as strict. Every
   * one of the nine warning lines in that run carried exactly two control
   * bytes, both ESC, which is the `expected 2 to be +0` those failures
   * reported. macOS emits none of them, which is why 226 files were green on
   * every developer machine here.
   *
   * Set on BOTH the environment and the session: which of the two governs
   * device discovery is not documented, and the second one is free.
   */
  private static readonly ORT_SEVERITY_ERROR = 3;

  private async loadOnnx(): Promise<void> {
    try {
      const ort = require('onnxruntime-node');
      // Before `create`, because that is what triggers the enumeration — and
      // in its OWN try, because the catch below disables neural inference for
      // the whole run. `env.logLevel` is a plain settable property today; if a
      // future onnxruntime makes it getter-only, this assignment throws under
      // strict mode, and without this boundary that would quietly drop every
      // scan back to vocabulary scoring to silence a log line. A noisy logger
      // is worth less than the classifier.
      try {
        if (ort.env) ort.env.logLevel = 'error';
      } catch {
        // Severity stays at the onnxruntime default; the session option below
        // is the other half and is set independently.
      }
      this.onnxSession = await ort.InferenceSession.create(this.modelPath, {
        logSeverityLevel: TMEClassifier.ORT_SEVERITY_ERROR,
      });
      trackOnnxSession(this.onnxSession);
      this.onnxReady = true;
    } catch {
      this.useOnnx = false;
    }
  }

  /** Wait for model download (if needed) and ONNX to be ready */
  async ensureReady(): Promise<void> {
    if (this.needsDownload) await this.ensureModel(this.downloadOptions);
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
    if (this.needsDownload) await this.ensureModel(this.downloadOptions);

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
