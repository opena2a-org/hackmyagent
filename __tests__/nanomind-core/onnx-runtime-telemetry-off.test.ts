/**
 * The ONNX runtime this tool loads for NanoMind inference writes no telemetry
 * store and no device identifier.
 *
 * Official onnxruntime builds from 1.29.0 on carry a telemetry client that is
 * on by default on macOS and Linux. Upstream documents that it keeps a
 * persistent device identifier and a queue of events, and that
 * `ORT_DISABLE_TELEMETRY=1`, set before the runtime initialises, prevents the
 * uploader, the events and the identifier. Measured with 1.30.0 on macOS
 * arm64 under an empty HOME: the first session a process creates writes
 * `$HOME/Library/Application Support/Microsoft/DeveloperTools/.onnxruntime/`
 * holding `deviceid` and `onnxruntime.db`, even when the model bytes do not
 * parse. With the variable in the environment at start, or assigned to
 * `process.env` before the require, it writes nothing. 1.27.0, the version
 * this repository's lockfile resolves, carries no such client: its native
 * libraries contain none of the variable, the store path or the collector
 * URL. `package.json` declares `^1.27.0`, so a fresh install of this tool
 * resolves the newest 1.x release, which can carry it.
 *
 * Four layers:
 *  1. Source: every load of onnxruntime-node in `src/` is in one function,
 *     and that function assigns the variable before it requires the package.
 *  2. In process: the classifier's ONNX path, with the package replaced by a
 *     recorder, requires it only after the variable reads '1'.
 *  3. Spawned: a `secure` scan under an empty HOME, on the real runtime,
 *     reaches session creation and leaves no store anywhere under that HOME
 *     or its temporary directory. The control is a direct initialisation of
 *     the same runtime that bypasses this tool's loader: it writes the store
 *     exactly when the runtime's native library carries the client.
 *  4. The docs: docs/onnxruntime-telemetry.md names the range `package.json`
 *     declares, the variable and the store, and the Semantic layer step of
 *     docs/how-it-works.md, the page the README links for it, names the
 *     variable and links that page.
 *
 * Layer 3 on another runtime: set HMA_TEST_ONNXRUNTIME_NODE to the directory
 * of an onnxruntime-node install (for example a fresh `npm install
 * onnxruntime-node@1.30.0` in a scratch directory) and both spawned runs load
 * that one. With 1.30.0 the control writes the store and the scan must not.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import Module, { createRequire } from 'node:module';
import path from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { assertDistFresh } from '../helpers/dist-freshness';
import { MODEL_FILES, TMEClassifier } from '../../src/nanomind-core/inference/tme-classifier';

const REPO_ROOT = path.join(__dirname, '..', '..');
const SRC = path.join(REPO_ROOT, 'src');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const PROBE_PRELOAD = path.join(__dirname, '..', 'fixtures', 'onnxruntime-probe-preload.cjs');
const HASH_PRELOAD = path.join(__dirname, '..', 'fixtures', 'stub-model-hash-preload.cjs');
const LOADER = path.join('nanomind-core', 'inference', 'onnx-runtime.ts');
const ASSIGNMENT = "process.env.ORT_DISABLE_TELEMETRY = '1';";

/** Names the runtime's telemetry client gives its store, at any depth. */
const STORE_NAMES = new Set(['DeveloperTools', '.onnxruntime', 'deviceid', 'onnxruntime.db']);

const SOUL = `# SOUL.md

## Identity
You are a documentation assistant for an internal wiki.

## Constraints
- Never execute shell commands.
- Only read files under docs/.

## Trust hierarchy
System prompt > operator > user > tool output.
`;

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...tsFiles(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

/** Every path under `root` with a segment the telemetry store is named by. */
function storePaths(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = path.join(dir, entry);
      if (STORE_NAMES.has(entry)) out.push(path.relative(root, full));
      if (statSync(full).isDirectory()) walk(full);
    }
  };
  walk(root);
  return out.sort();
}

/** Stand-in model files at the pinned sizes, as `onnx-session-release.test.ts` writes them. */
function writeStandInModel(dir: string): void {
  mkdirSync(dir, { recursive: true });
  for (const { name, bytes } of MODEL_FILES) {
    writeFileSync(
      path.join(dir, name),
      name === 'tokenizer.json' ? '{"the": 2}'.padEnd(bytes, '\n') : Buffer.alloc(bytes),
    );
  }
}

/** The onnxruntime-node directory both spawned runs load. */
function runtimeDir(): string {
  const alternate = process.env.HMA_TEST_ONNXRUNTIME_NODE;
  if (alternate) return path.resolve(alternate);
  return path.dirname(createRequire(path.join(REPO_ROOT, 'package.json')).resolve('onnxruntime-node/package.json'));
}

/**
 * True when the runtime's native library for this host carries the telemetry
 * client. Its opt-out variable is compiled into the library as a string when
 * the client is; 1.27.0 has it in no platform's library and 1.30.0 has it in
 * the macOS one.
 */
function runtimeCarriesTelemetryClient(dir: string): boolean {
  const native = path.join(dir, 'bin', 'napi-v6', process.platform, process.arch);
  const libraries = readdirSync(native).filter((f) => /onnxruntime/.test(f) && !f.includes('binding'));
  expect(libraries.length, `no onnxruntime library under ${native}`).toBeGreaterThan(0);
  return libraries.some((f) => readFileSync(path.join(native, f)).includes('ORT_DISABLE_TELEMETRY'));
}

/**
 * An environment rooted in `root`: an empty HOME, the cache, data, config and
 * state directories and TMPDIR inside it, and no ORT_DISABLE_TELEMETRY. That
 * variable is removed because this worker may already have assigned it, and
 * a child that inherited it would pass whatever the code under test does.
 */
function freshEnvironment(root: string): NodeJS.ProcessEnv {
  const home = path.join(root, 'home');
  const tmp = path.join(root, 'tmp');
  mkdirSync(home, { recursive: true });
  mkdirSync(tmp, { recursive: true });
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, TMPDIR: tmp, NO_COLOR: '1' };
  for (const name of ['XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'ORT_DISABLE_TELEMETRY']) {
    delete env[name];
  }
  // No hosted-model request: this run measures the local runtime only.
  delete env.ANTHROPIC_API_KEY;
  if (process.env.HMA_TEST_ONNXRUNTIME_NODE) env.HMA_TEST_ONNXRUNTIME_NODE = runtimeDir();
  return env;
}

describe('every load of onnxruntime-node turns its telemetry off first', () => {
  it('src/ loads onnxruntime-node in one function, and assigns ORT_DISABLE_TELEMETRY before it', () => {
    const loads: Array<{ file: string; at: number }> = [];
    const pattern = /require\(\s*['"]onnxruntime-node['"]\s*\)|from\s+['"]onnxruntime-node['"]|import\(\s*['"]onnxruntime-node['"]\s*\)/g;
    for (const file of tsFiles(SRC)) {
      const text = readFileSync(file, 'utf8');
      for (const m of text.matchAll(pattern)) loads.push({ file: path.relative(SRC, file), at: m.index ?? -1 });
    }
    expect(loads.map((l) => l.file)).toEqual([LOADER]);

    const loader = readFileSync(path.join(SRC, LOADER), 'utf8');
    const assigned = loader.indexOf(ASSIGNMENT);
    expect(assigned, `${LOADER} does not contain ${ASSIGNMENT}`).toBeGreaterThan(-1);
    expect(assigned, 'the assignment comes after the require').toBeLessThan(loads[0].at);
  });

  it('the classifier requires onnxruntime-node only after ORT_DISABLE_TELEMETRY reads 1', async () => {
    const models = tempDir('hma-ort-telemetry-models-');
    writeStandInModel(models);
    const pinned = Object.fromEntries(MODEL_FILES.map((f) => [f.name, f.sha256]));

    const atRequire: string[] = [];
    let created = 0;
    const recorder = {
      env: {},
      Tensor: class Tensor {
        constructor(public type: string, public data: unknown, public dims: number[]) {}
      },
      InferenceSession: {
        async create() {
          created += 1;
          return {
            async run() {
              return { logits: { data: new Float32Array(10) } };
            },
            async release() {},
          };
        },
      },
    };

    const loader = Module as unknown as { _load: (request: string, ...rest: unknown[]) => unknown };
    const classifier = TMEClassifier as unknown as {
      hashFileBytes: (filePath: string, bytes: Uint8Array) => string;
    };
    const realLoad = loader._load;
    const realHash = classifier.hashFileBytes;
    const saved = process.env.ORT_DISABLE_TELEMETRY;
    delete process.env.ORT_DISABLE_TELEMETRY;
    loader._load = function load(this: unknown, request: string, ...rest: unknown[]) {
      if (request === 'onnxruntime-node') {
        atRequire.push(process.env.ORT_DISABLE_TELEMETRY ?? '<unset>');
        return recorder;
      }
      return realLoad.call(this, request, ...rest);
    };
    classifier.hashFileBytes = (filePath, bytes) => {
      const resolved = path.resolve(filePath);
      const sha = pinned[path.basename(resolved)];
      if (sha && path.dirname(resolved) === path.resolve(models)) return sha;
      return realHash.call(TMEClassifier, filePath, bytes);
    };
    try {
      await new TMEClassifier(models).classifyAsync('Summarise the attached report for the team.');
    } finally {
      loader._load = realLoad;
      classifier.hashFileBytes = realHash;
      if (saved === undefined) delete process.env.ORT_DISABLE_TELEMETRY;
      else process.env.ORT_DISABLE_TELEMETRY = saved;
    }

    // Non-vacuity: the ONNX path ran, through the recorder, to session creation.
    expect(created, 'the classifier created no ONNX session').toBe(1);
    expect(atRequire.length, 'the classifier never required onnxruntime-node').toBeGreaterThan(0);
    expect(atRequire, 'ORT_DISABLE_TELEMETRY at each require of onnxruntime-node').toEqual(
      atRequire.map(() => '1'),
    );
  });
});

describe('a scan under an empty HOME leaves no ONNX runtime telemetry store', () => {
  beforeAll(assertDistFresh);

  it('the control: a direct initialisation that bypasses the loader writes the store exactly when the runtime carries the client', () => {
    const dir = runtimeDir();
    const carries = runtimeCarriesTelemetryClient(dir);
    const root = tempDir('hma-ort-telemetry-control-');
    const env = freshEnvironment(root);
    const code = [
      'const ort = require(process.argv[1]);',
      'ort.InferenceSession.create(Buffer.from([0])).then(',
      "  () => process.stdout.write('created\\n'),",
      "  (e) => process.stdout.write('refused: ' + String(e && e.message).slice(0, 80) + '\\n'),",
      ');',
    ].join('\n');
    const res = spawnSync(process.execPath, ['-e', code, dir], { cwd: root, env, encoding: 'utf8', timeout: 60_000 });
    expect(res.status, res.stderr).toBe(0);
    // The runtime was initialised: zero bytes parse as no model, after the
    // environment the client starts in is set up.
    expect(res.stdout).toMatch(/^refused: /);
    const written = storePaths(root);
    if (carries) {
      expect(written, 'a runtime that carries the client wrote no store, so the scan below proves nothing').toEqual(
        expect.arrayContaining(['deviceid', 'onnxruntime.db'].map((f) => expect.stringContaining(f))),
      );
    } else {
      expect(written, 'a runtime without the client wrote a store').toEqual([]);
    }
  });

  it('secure creates an ONNX session on the real runtime and writes nothing the client stores', () => {
    const root = tempDir('hma-ort-telemetry-scan-');
    const env = freshEnvironment(root);
    const models = path.join(env.HOME as string, '.nanomind', 'models');
    writeStandInModel(models);
    const target = path.join(root, 'target');
    mkdirSync(target);
    writeFileSync(path.join(target, 'SOUL.md'), SOUL);
    env.NODE_OPTIONS = `--require ${PROBE_PRELOAD} --require ${HASH_PRELOAD}`;
    env.HMA_TEST_STAND_IN_MODEL_DIR = models;

    const res = spawnSync(process.execPath, [CLI, 'secure', target, '--json'], {
      cwd: root,
      env,
      encoding: 'utf8',
      timeout: 120_000,
    });
    const stderr = res.stderr ?? '';
    expect([0, 1, 2], `secure ended with ${res.status}: ${stderr.slice(-2000)}`).toContain(res.status);
    expect(stderr, 'the scan downloaded the model instead of using the stand-in cache').not.toContain(
      'NanoMind: downloading',
    );

    // The child started without the variable, so only the code under test can set it.
    expect(stderr).toMatch(/^ORT-PROBE start ORT_DISABLE_TELEMETRY=<unset>$/m);
    const creates = [...stderr.matchAll(/^ORT-PROBE create ORT_DISABLE_TELEMETRY=(\S+) onnxruntime-node=(\S+)$/gm)];
    expect(creates.length, 'the scan created no ONNX session, so it cannot show the runtime wrote nothing').toBeGreaterThan(0);
    const version = JSON.parse(readFileSync(path.join(runtimeDir(), 'package.json'), 'utf8')).version;
    expect(creates.map((m) => m[2])).toEqual(creates.map(() => version));

    expect(storePaths(root), 'the ONNX runtime wrote its telemetry store during the scan').toEqual([]);
    // On a runtime without the client the store check above passes whatever
    // the code does; this is the half that holds on every runtime.
    expect(creates.map((m) => m[1]), 'ORT_DISABLE_TELEMETRY at each session creation').toEqual(
      creates.map(() => '1'),
    );
  });
});

describe('the docs page and the How it works step that links it', () => {
  const pkg = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
  const HOW_IT_WORKS = readFileSync(path.join(REPO_ROOT, 'docs', 'how-it-works.md'), 'utf8');
  const PAGE = readFileSync(path.join(REPO_ROOT, 'docs', 'onnxruntime-telemetry.md'), 'utf8');
  const declared: string = pkg.dependencies['onnxruntime-node'];

  it('docs/onnxruntime-telemetry.md names the range package.json declares, the variable and the store', () => {
    expect(PAGE).toContain(`\`onnxruntime-node\` \`${declared}\``);
    expect(PAGE).toContain('`ORT_DISABLE_TELEMETRY=1`');
    expect(PAGE).toContain('Microsoft/DeveloperTools/.onnxruntime');
  });

  it('the Semantic layer step of docs/how-it-works.md names the variable and links the page', () => {
    const step = HOW_IT_WORKS.split('\n').find((line) => line.includes('**Semantic layer.**'));
    expect(step, 'docs/how-it-works.md has no Semantic layer step').toBeDefined();
    expect(step).toContain('`ORT_DISABLE_TELEMETRY=1`');
    expect(step).toContain('](onnxruntime-telemetry.md)');
  });
});
