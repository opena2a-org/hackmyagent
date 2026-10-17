#!/usr/bin/env node
/**
 * The example output behind the choices in docs/chooser.json.
 *
 * An entry's `example` names a committed fixture folder, the entry's command
 * with each operand filled in (`args`), the exit code that run ends with
 * (`exit`) and its capture file under docs/captures/. For each example this
 * script copies the fixture into a new temporary folder under the fixture's
 * own name, runs `node dist/cli.js <args>` inside that copy, and holds the run
 * to three files:
 *
 *   - docs/chooser.json: the run ends with the exit code the example declares;
 *   - the capture: standard output and standard error, in the order the CLI
 *     wrote them, with the normalizers below applied, are byte-equal to it;
 *   - the sidecar beside the capture (`<id>.json`): it is the record this
 *     script renders for the example, naming the command, the fixture, the
 *     exit code, the environment and the normalizers.
 *
 * The normalizers, applied in this order, each listed in every sidecar:
 *
 *   classifier-download  the NanoMind classifier download notice is removed
 *   temp-folder          the temporary folder holding the fixture copy prints as `...`
 *   tool-version         the version on the `Scanned with hackmyagent` line prints as `<version>`
 *   duration             a `Duration:` count of milliseconds prints as `<n>ms`
 *   trailing-space       spaces and tabs at the end of a line are removed
 *
 * Usage (after `npm run build`):
 *   node scripts/chooser-captures.mjs           compare every capture and sidecar with a fresh run
 *   node scripts/chooser-captures.mjs --write   rewrite every capture and sidecar from a fresh run
 *
 * `--write` records no run whose exit code differs from the declared one: the
 * exit code is a statement in docs/chooser.json, and a run that contradicts it
 * is reported, not captured.
 *
 * Exit codes: 0 every exit code, capture and sidecar matches (or was
 * written), 1 one of them differs, 2 nothing could be compared (no build,
 * invalid data, a missing fixture, the classifier could not be fetched, an
 * unknown argument).
 */
import { spawnSync } from 'node:child_process';
import {
  closeSync, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DATA, commandLine, validateChooser } from './chooser.mjs';
import { CLI, DOWNLOAD_FAILED, DOWNLOAD_NOTICE, seedClassifier } from './use-case-samples.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Each normalizer: its id, the sentence a sidecar shows for it, and the rewrite. */
export const NORMALIZERS = [
  {
    id: 'classifier-download',
    does: 'Removes the NanoMind classifier download notice, which a run on an empty model cache prints and a later run does not.',
    apply: (text) => text.split('\n').filter((l) => !DOWNLOAD_NOTICE.some((re) => re.test(l))).join('\n'),
  },
  {
    id: 'temp-folder',
    does: 'Prints the temporary folder that holds the fixture copy as "...", so a path reads ".../insecure-library/.env".',
    // Longest first: on macOS the temp folder `/var/...` is a suffix of its
    // real path `/private/var/...`, and replacing it first leaves `/private...`.
    apply: (text, { folders }) =>
      [...folders].sort((a, b) => b.length - a.length).reduce((t, f) => t.split(`${f}${path.sep}`).join('.../'), text),
  },
  {
    id: 'tool-version',
    does: 'Prints the version on the "Scanned with hackmyagent" line as <version>, so a release alone changes no capture.',
    apply: (text) => text.replace(/^( *Scanned with hackmyagent v)\S+$/gm, '$1<version>'),
  },
  {
    id: 'duration',
    does: 'Prints a "Duration:" count of milliseconds as <n>ms.',
    apply: (text) => text.replace(/^( *Duration: +)\d+ms$/gm, '$1<n>ms'),
  },
  {
    id: 'trailing-space',
    does: 'Removes spaces and tabs at the end of each line.',
    apply: (text) => text.replace(/[ \t]+$/gm, ''),
  },
];

/** `raw` with the normalizers named by `ids` applied in that order; `folders` are the temporary folders of the run. */
export function normalize(raw, ids, { folders = [] } = {}) {
  return ids.reduce((text, id) => {
    const n = NORMALIZERS.find((x) => x.id === id);
    if (!n) throw new Error(`unknown normalizer "${id}"`);
    return n.apply(text, { folders });
  }, raw);
}

/** Every entry of the data that carries an example, options first. */
export function examples(data) {
  return [...data.options, ...data.more].filter((e) => e.example !== undefined);
}

/** The sidecar path for a capture path: the same name, ending in .json. */
export function sidecarPath(capture) {
  return capture.replace(/\.txt$/, '.json');
}

const PASSED_THROUGH = ['PATH', 'HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'NO_PROXY', 'no_proxy'];
const SET = { LANG: 'en_US.UTF-8', NO_COLOR: '1', OPENA2A_TELEMETRY: 'off' };

/** The sidecar text for `entry`, as --write writes it. */
export function renderSidecar(data, entry) {
  const ex = entry.example;
  const record = {
    about: `How ${ex.capture} was made, from the ${entry.id} entry of docs/chooser.json. scripts/chooser-captures.mjs writes both files; regenerate them with node scripts/chooser-captures.mjs --write.`,
    choice: entry.id,
    command: commandLine(data, ex.args),
    ranAs: `node dist/cli.js ${ex.args}`,
    fixture: ex.fixture,
    ranIn: 'a copy of the fixture folder, under its own name, in a new temporary folder',
    exit: ex.exit,
    environment: {
      HOME: 'a new temporary folder',
      TMPDIR: 'the temporary folder of the process that ran the script',
      ...SET,
      passedThrough: PASSED_THROUGH,
    },
    output: 'standard output and standard error in one file, in the order the command wrote them',
    capture: ex.capture,
    normalizers: NORMALIZERS.map(({ id, does }) => ({ id, does })),
  };
  return `${JSON.stringify(record, null, 2)}\n`;
}

/**
 * Run `entry`'s example against a fresh copy of its fixture, with `home` as
 * HOME. Pass one HOME to every run so the classifier is fetched at most once.
 * Returns the exit status, the raw output, whether the classifier could be
 * used, and the temporary folders the temp-folder normalizer replaces.
 */
export function runExample(entry, { home, cli = CLI, timeoutMs = 150_000 }) {
  const ex = entry.example;
  const source = path.join(REPO_ROOT, ex.fixture);
  if (!existsSync(source) || !statSync(source).isDirectory()) {
    throw new Error(`${entry.id}: the fixture ${ex.fixture} is not a folder in this repository`);
  }
  const parent = mkdtempSync(path.join(os.tmpdir(), 'hma-chooser-'));
  try {
    const dir = path.join(parent, path.basename(ex.fixture));
    cpSync(source, dir, { recursive: true });
    const out = path.join(parent, 'output.txt');
    const fd = openSync(out, 'w');
    let r;
    try {
      r = spawnSync(process.execPath, [cli, ...ex.args.split(/\s+/)], {
        cwd: dir,
        stdio: ['ignore', fd, fd],
        timeout: timeoutMs,
        env: {
          ...Object.fromEntries(PASSED_THROUGH.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]])),
          HOME: home,
          TMPDIR: os.tmpdir(),
          ...SET,
        },
      });
    } finally {
      closeSync(fd);
    }
    if (r.error || r.status === null) {
      throw new Error(`${entry.id}: ${ex.args} did not finish: ${r.error?.message ?? r.signal}`);
    }
    const raw = readFileSync(out, 'utf8');
    return {
      status: r.status,
      raw,
      classifier: !raw.split('\n').some((l) => DOWNLOAD_FAILED.test(l)),
      folders: [...new Set([parent, realpathSync(parent)])],
    };
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
}

/** null when `have` and `want` are the same bytes; otherwise the first differing line, 1-based. */
export function compareText(have, want) {
  if (have === want) return null;
  const a = have.split('\n');
  const b = want.split('\n');
  let i = 0;
  while (i < Math.max(a.length, b.length) && a[i] === b[i]) i++;
  return { line: i + 1, have: a[i], want: b[i] };
}

function readOrNull(rel) {
  try {
    return readFileSync(path.join(REPO_ROOT, rel), 'utf8');
  } catch {
    return null;
  }
}

function main(argv) {
  const write = argv.includes('--write');
  const unknown = argv.filter((a) => a !== '--write');
  if (unknown.length) {
    process.stderr.write(`chooser-captures: unexpected argument "${unknown[0]}"\nUsage: node scripts/chooser-captures.mjs [--write]\n`);
    return 2;
  }
  if (!existsSync(CLI)) {
    process.stderr.write('chooser-captures: dist/cli.js is missing; run `npm run build` first\n');
    return 2;
  }
  const data = JSON.parse(readFileSync(DATA, 'utf8'));
  const problems = validateChooser(data);
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`chooser-captures: docs/chooser.json: ${p}\n`);
    return 2;
  }
  const ids = NORMALIZERS.map((n) => n.id);
  const home = mkdtempSync(path.join(os.tmpdir(), 'hma-chooser-home-'));
  let exitDiffer = 0;
  let differ = 0;
  try {
    seedClassifier(home);
    for (const entry of examples(data)) {
      const ex = entry.example;
      const label = `${entry.id}: ${commandLine(data, ex.args)}`;
      const run = runExample(entry, { home });
      if (!run.classifier) {
        process.stderr.write(`${label}: the NanoMind classifier could not be fetched, and the captures are runs with it\n`);
        return 2;
      }
      if (run.status !== ex.exit) {
        exitDiffer++;
        process.stdout.write(`${label}: exited ${run.status}; docs/chooser.json declares ${ex.exit}\n`);
        continue;
      }
      const output = normalize(run.raw, ids, run);
      const sidecar = renderSidecar(data, entry);
      if (write) {
        mkdirSync(path.dirname(path.join(REPO_ROOT, ex.capture)), { recursive: true });
        writeFileSync(path.join(REPO_ROOT, ex.capture), output);
        writeFileSync(path.join(REPO_ROOT, sidecarPath(ex.capture)), sidecar);
        process.stdout.write(`${label}: exit ${run.status}; ${ex.capture} and its sidecar written\n`);
        continue;
      }
      let same = true;
      for (const [file, fresh] of [[ex.capture, output], [sidecarPath(ex.capture), sidecar]]) {
        const have = readOrNull(file);
        const d = have === null ? null : compareText(have, fresh);
        if (have === null) process.stdout.write(`${label}: ${file} is missing\n`);
        else if (d) process.stdout.write(`${label}: ${file}:${d.line} differs\n  file:  ${d.have ?? '(none)'}\n  fresh: ${d.want ?? '(none)'}\n`);
        if (have === null || d) same = false;
      }
      if (same) process.stdout.write(`${label}: exit ${run.status}; capture and sidecar match\n`);
      else differ++;
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
  if (exitDiffer) {
    process.stdout.write(
      `${exitDiffer} example(s) exited with a code docs/chooser.json does not declare; ` +
        `${write ? 'their files were left as they were' : '--write records none of them'}. Change the fixture or the declared code.\n`,
    );
  }
  if (differ) process.stdout.write(`${differ} example(s) differ from a fresh run. Regenerate: node scripts/chooser-captures.mjs --write\n`);
  return exitDiffer || differ ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (err) {
    process.stderr.write(`chooser-captures failed: ${err.message}\n`);
    process.exit(2);
  }
}
