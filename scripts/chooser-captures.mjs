#!/usr/bin/env node
/**
 * The example output behind the choices in docs/chooser.json.
 *
 * An entry's `example` names a committed fixture folder, the entry's command
 * with each operand filled in (`args`), the exit code that run ends with
 * (`exit`) and its capture file under docs/captures/. A `nextExample` does the
 * same for the entry's next command. For each example this script copies the
 * fixture into a new temporary folder under the fixture's own name, runs
 * `node dist/cli.js <args>` inside that copy, and holds the run to three
 * files. An example whose `args` have the operand `-` names the file of the
 * fixture the run reads on standard input (`stdin`); every other run reads
 * nothing there. An example that names a `materialize` script of its fixture
 * is not copied: the script writes the fixture into that folder instead, as
 * test-fixtures/demo-agents/materialize.mjs does for the projects whose fake
 * credentials are not committed whole.
 *
 * An example that names a `serve` script of its fixture sends its command to
 * a server. The script runs in the fixture copy with the path of a file as its
 * one argument, listens on a free port of 127.0.0.1 and writes that port to
 * the file; the command runs with that port in place of `<port>` in `args`,
 * and the server is stopped once the command ends. The script also stops when
 * its standard input closes, so a server whose runner is killed does not keep
 * the port. test-fixtures/exposed-mcp-host/serve.mjs is one.
 *
 * Each example runs the command a reader copies, options and their defaults
 * included. `attack` waits 1000 ms after each payload unless `--delay` says
 * otherwise, and its examples pass no `--delay`, so a run of
 * `attack <url> --intensity aggressive` lasts at least 164 seconds, one for
 * each payload it sends. A command that has not ended after RUN_LIMIT_MS is
 * stopped and reported.
 *
 * `detect` adds what it finds on the machine to every report: the processes
 * running there, which no fixture holds. A run of `detect` finds `ps` first
 * on PATH as a script that lists no process, so it reports what a machine
 * running no AI tool reports; the sidecar of such a run says so.
 *
 *   - docs/chooser.json: the run ends with the exit code the example declares;
 *   - the capture: standard output and standard error, in the order the CLI
 *     wrote them, with the normalizers below applied, are byte-equal to it;
 *   - the sidecar beside the capture (`<id>.json`): it is the record this
 *     script renders for the example, naming the command, the fixture, the
 *     exit code, the environment and the normalizers.
 *
 * The normalizers, applied in this order, each listed in the sidecar of every
 * run it applies to:
 *
 *   classifier-download  the NanoMind classifier download notice is removed
 *   temp-folder          the temporary folder holding the fixture copy prints as `...`
 *   served-port          (serve runs) the port the fixture's server listened on prints as `<port>`
 *   home-folder         (--fix runs) the HOME folder of the run prints as `~`
 *   backup-store         (--fix runs) the backup folder names print as `<directory>` and `<run>`
 *   host-name            (detect runs) the machine name on the `shadow ai audit` line prints as `<host>`
 *   tool-version         the version on the `Scanned with hackmyagent` line prints as `<version>`
 *   json-version         (--json runs) the `hackmyagentVersion` value prints as `<version>`
 *   duration             a `Duration:` count of milliseconds prints as `<n>ms`
 *   trailing-space       spaces and tabs at the end of a line are removed
 *
 * A run whose `args` include `--fix` keeps a backup of the files it changed in
 * a store under HOME and prints where; home-folder and backup-store apply to
 * those runs only, so the record of a run that prints no backup lists neither.
 * json-version applies to runs whose `args` include `--json` only,
 * host-name to runs of `detect` only and served-port to runs whose `args`
 * name `<port>` only, for the same reason.
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
 * invalid data, a missing fixture, a materialize script that did not write
 * its fixture, a serve script that wrote no port, the classifier could not be
 * fetched, an unknown argument).
 */
import { spawn, spawnSync } from 'node:child_process';
import {
  closeSync, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DATA, EXAMPLE_FIELDS, PORT_SLOT, commandLine, namesPort, validateChooser } from './chooser.mjs';
import { CLI, DOWNLOAD_FAILED, DOWNLOAD_NOTICE, seedClassifier } from './use-case-samples.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** How long one example's command may run before it is stopped: above the 164 s the aggressive attack example waits between payloads. */
export const RUN_LIMIT_MS = 240_000;

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
    id: 'served-port',
    serveOnly: true,
    does: 'Prints the port the fixture\'s server listened on, a free one chosen at run time, as <port> wherever that number stands alone.',
    apply: (text, { ports }) =>
      ports.reduce((t, p) => t.replace(new RegExp(`(?<![0-9])${p}(?![0-9])`, 'g'), PORT_SLOT), text),
  },
  {
    id: 'home-folder',
    fixOnly: true,
    does: 'Prints the HOME folder of the run, a new temporary folder, as "~", so the --fix backup reads "~/.opena2a/backups/...".',
    // Longest first, for the same reason as temp-folder.
    apply: (text, { homes }) =>
      [...homes].sort((a, b) => b.length - a.length).reduce((t, h) => t.split(`${h}${path.sep}`).join('~/'), text),
  },
  {
    id: 'backup-store',
    fixOnly: true,
    does: 'Prints the folder the --fix backup store keeps for the scanned directory as <directory> and the folder of this run\'s backup as <run>: the first is named from the device, inode and creation time of the fixture copy, the second from the time of the run and a random part.',
    apply: (text) =>
      text.replace(
        /(\.opena2a\/backups\/)\d+-\d+-\d+(\/\d{4}-\d{2}-\d{2}-\d{9}-\d{3}-[0-9a-f]{8})?/g,
        (_, store, run) => `${store}<directory>${run ? '/<run>' : ''}`,
      ),
  },
  {
    id: 'host-name',
    detectOnly: true,
    does: 'Prints the name of the machine on the "shadow ai audit" header line as <host>.',
    apply: (text) => text.replace(/^(.* shadow ai audit · )[^\s·]+/gm, '$1<host>'),
  },
  {
    id: 'tool-version',
    does: 'Prints the version on the "Scanned with hackmyagent" line as <version>, so a release alone changes no capture.',
    apply: (text) => text.replace(/^( *Scanned with hackmyagent v)\S+$/gm, '$1<version>'),
  },
  {
    id: 'json-version',
    jsonOnly: true,
    does: 'Prints the "hackmyagentVersion" value of the --json document as <version>, so a release alone changes no capture.',
    apply: (text) => text.replace(/^( *"hackmyagentVersion": ")[^"]*(",?)$/gm, '$1<version>$2'),
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

/** The normalizers that apply to a run of `args`, in the order they are applied. */
export function normalizersFor(args) {
  const words = args.split(/\s+/);
  const fix = words.includes('--fix');
  const json = words.includes('--json');
  const detect = readsProcessList(args);
  const serve = namesPort(args);
  return NORMALIZERS.filter(
    (n) => (fix || !n.fixOnly) && (json || !n.jsonOnly) && (detect || !n.detectOnly) && (serve || !n.serveOnly),
  );
}

/** True when the command of `args` is `detect`, which adds the processes running on the machine to its report. */
export function readsProcessList(args) {
  return args.split(/\s+/)[0] === 'detect';
}

/** The `ps` a run of `detect` finds first on PATH: the header line of `ps aux`, and no process. */
const NO_PROCESS_PS = '#!/bin/sh\necho "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND"\n';

/**
 * The command line a reader types to make the example's output: the command,
 * and for an example that reads standard input, the fixture file it reads
 * there.
 */
export function exampleCommand(data, ex) {
  return `${commandLine(data, ex.args)}${stdinRedirect(ex)}`;
}

/** ` < <file>` for an example that reads standard input, and nothing for any other. */
function stdinRedirect(ex) {
  return ex.stdin === undefined ? '' : ` < ${ex.stdin}`;
}

/**
 * `raw` with the normalizers named by `ids` applied in that order; `folders`
 * are the temporary folders of the run, `homes` its HOME folder and `ports`
 * the port its fixture's server listened on.
 */
export function normalize(raw, ids, { folders = [], homes = [], ports = [] } = {}) {
  return ids.reduce((text, id) => {
    const n = NORMALIZERS.find((x) => x.id === id);
    if (!n) throw new Error(`unknown normalizer "${id}"`);
    return n.apply(text, { folders, homes, ports });
  }, raw);
}

/**
 * Every example of the data, options first and an entry's `example` before
 * its `nextExample`: the entry, the command the example runs (`run` or
 * `next`) and the example.
 */
export function examples(data) {
  return [...data.options, ...data.more].flatMap((entry) =>
    EXAMPLE_FIELDS.filter(({ field }) => entry[field] !== undefined).map(({ field, command }) => ({
      entry,
      step: command,
      example: entry[field],
    })),
  );
}

/** The sidecar path for a capture path: the same name, ending in .json. */
export function sidecarPath(capture) {
  return capture.replace(/\.txt$/, '.json');
}

const PASSED_THROUGH = ['PATH', 'HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'NO_PROXY', 'no_proxy'];
const SET = { LANG: 'en_US.UTF-8', NO_COLOR: '1', OPENA2A_TELEMETRY: 'off' };

/** The sidecar text for `item`, one of `examples(data)`, as --write writes it. */
export function renderSidecar(data, item) {
  const { entry, step, example: ex } = item;
  const from = step === 'next' ? `the next command of the ${entry.id} entry` : `the ${entry.id} entry`;
  const record = {
    about: `How ${ex.capture} was made, from ${from} of docs/chooser.json. scripts/chooser-captures.mjs writes both files; regenerate them with node scripts/chooser-captures.mjs --write.`,
    choice: entry.id,
    command: exampleCommand(data, ex),
    ranAs: `node dist/cli.js ${ex.args}${stdinRedirect(ex)}`,
    fixture: ex.fixture,
    ...(ex.stdin === undefined ? {} : { stdin: `${ex.stdin}, a file of the fixture, read on standard input` }),
    ranIn: ex.materialize === undefined
      ? 'a copy of the fixture folder, under its own name, in a new temporary folder'
      : `the folder ${ex.fixture}/${ex.materialize} writes, under the fixture's own name, in a new temporary folder`,
    ...(ex.serve === undefined
      ? {}
      : { served: `by ${ex.serve} of the fixture, started there before the command and stopped after it; ${PORT_SLOT} is the free port it listened on` }),
    exit: ex.exit,
    environment: {
      HOME: 'a new temporary folder',
      TMPDIR: 'the temporary folder of the process that ran the script',
      ...SET,
      passedThrough: PASSED_THROUGH,
      ...(readsProcessList(ex.args)
        ? { ps: 'first on PATH, a script that lists no process, so the run reports no AI tool running on the machine that made it' }
        : {}),
    },
    output: 'standard output and standard error in one file, in the order the command wrote them',
    capture: ex.capture,
    normalizers: normalizersFor(ex.args).map(({ id, does }) => ({ id, does })),
  };
  return `${JSON.stringify(record, null, 2)}\n`;
}

/**
 * Write the fixture of `item` into `dir` with the fixture's `materialize`
 * script, which takes the folder to write as its one argument and exits 0
 * when it wrote it.
 */
function materializeFixture(item, source, dir, env) {
  const { entry, example: ex } = item;
  const script = path.join(source, ex.materialize);
  if (!existsSync(script) || !statSync(script).isFile()) {
    throw new Error(`${entry.id}: the fixture ${ex.fixture} has no script ${ex.materialize} to write it with`);
  }
  const r = spawnSync(process.execPath, [script, dir], { encoding: 'utf8', env, timeout: 60_000 });
  if (r.error || r.status !== 0) {
    const why = r.error?.message ?? (r.status === null ? r.signal : `exit ${r.status}: ${r.stderr.trim().split('\n')[0]}`);
    throw new Error(`${entry.id}: ${ex.fixture}/${ex.materialize} did not write the fixture: ${why}`);
  }
}

/** Block this thread for `ms` milliseconds. */
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Start the server of `item` with the `serve` script of its fixture, run in
 * `dir` with `portFile` as its one argument, and wait up to `startMs`
 * milliseconds for the port it writes there. The server's standard input is a
 * pipe this process holds, so the server stops when this process ends.
 * Returns the server process and its port.
 */
function startServer(item, dir, portFile, env, startMs) {
  const { entry, example: ex } = item;
  const script = path.join(dir, ex.serve);
  if (!existsSync(script) || !statSync(script).isFile()) {
    throw new Error(`${entry.id}: the fixture ${ex.fixture} has no script ${ex.serve} to serve it with`);
  }
  const server = spawn(process.execPath, [script, portFile], { cwd: dir, env, stdio: ['pipe', 'ignore', 'ignore'] });
  // A signal that finds the server gone is no failure of the run.
  server.on('error', () => {});
  // The command runs with spawnSync, which holds this thread, so the wait for
  // the port polls the file instead of listening for an event.
  const deadline = Date.now() + startMs;
  for (;;) {
    const written = existsSync(portFile) ? /^(\d+)\n$/.exec(readFileSync(portFile, 'utf8')) : null;
    if (written) return { server, port: Number(written[1]) };
    if (Date.now() >= deadline) break;
    sleepSync(25);
  }
  stopServer(server);
  throw new Error(`${entry.id}: ${ex.fixture}/${ex.serve} wrote no port within ${startMs} ms`);
}

/** Close the server's standard input and send it SIGTERM. */
function stopServer(server) {
  server.stdin.destroy();
  server.kill();
}

/**
 * Run `item`, one of `examples(data)`, against a fresh copy of its fixture
 * (or the folder its `materialize` script writes), with `home` as HOME and,
 * when the example names one, the copy's `stdin` file on standard input. A
 * run of `detect` finds a `ps` that lists no process first on PATH. An example
 * that names a `serve` script runs with its server listening, which has
 * `serveStartMs` to write its port. Pass one HOME to every run so the
 * classifier is fetched at most once. Returns the exit status, the raw output,
 * whether the classifier could be used, the temporary folders the temp-folder
 * normalizer replaces, the HOME folders the home-folder normalizer replaces
 * and the port the served-port normalizer replaces (none for a run without a
 * server).
 */
export function runExample(item, { home, cli = CLI, timeoutMs = RUN_LIMIT_MS, serveStartMs = 10_000 }) {
  const { entry, example: ex } = item;
  const source = path.join(REPO_ROOT, ex.fixture);
  if (!existsSync(source) || !statSync(source).isDirectory()) {
    throw new Error(`${entry.id}: the fixture ${ex.fixture} is not a folder in this repository`);
  }
  const parent = mkdtempSync(path.join(os.tmpdir(), 'hma-chooser-'));
  try {
    const env = {
      ...Object.fromEntries(PASSED_THROUGH.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]])),
      HOME: home,
      TMPDIR: os.tmpdir(),
      ...SET,
    };
    const dir = path.join(parent, path.basename(ex.fixture));
    if (ex.materialize === undefined) cpSync(source, dir, { recursive: true });
    else materializeFixture(item, source, dir, env);
    if (readsProcessList(ex.args)) {
      const bin = path.join(parent, 'bin');
      mkdirSync(bin);
      writeFileSync(path.join(bin, 'ps'), NO_PROCESS_PS, { mode: 0o755 });
      env.PATH = `${bin}${path.delimiter}${env.PATH ?? ''}`;
    }
    let input = 'ignore';
    if (ex.stdin !== undefined) {
      const file = path.join(dir, ex.stdin);
      if (!existsSync(file) || !statSync(file).isFile()) {
        throw new Error(`${entry.id}: the fixture ${ex.fixture} has no file ${ex.stdin} to read on standard input`);
      }
      input = openSync(file, 'r');
    }
    const out = path.join(parent, 'output.txt');
    const fd = openSync(out, 'w');
    let r;
    let served = null;
    try {
      if (ex.serve !== undefined) served = startServer(item, dir, path.join(parent, 'port'), env, serveStartMs);
      const args = served === null ? ex.args : ex.args.split(PORT_SLOT).join(String(served.port));
      r = spawnSync(process.execPath, [cli, ...args.split(/\s+/)], {
        cwd: dir,
        stdio: [input, fd, fd],
        timeout: timeoutMs,
        env,
      });
    } finally {
      if (served !== null) stopServer(served.server);
      closeSync(fd);
      if (input !== 'ignore') closeSync(input);
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
      homes: [...new Set([home, realpathSync(home)])],
      ports: served === null ? [] : [served.port],
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
  const home = mkdtempSync(path.join(os.tmpdir(), 'hma-chooser-home-'));
  let exitDiffer = 0;
  let differ = 0;
  try {
    seedClassifier(home);
    for (const item of examples(data)) {
      const ex = item.example;
      const label = `${item.entry.id}${item.step === 'next' ? ' (next)' : ''}: ${exampleCommand(data, ex)}`;
      const run = runExample(item, { home });
      if (!run.classifier) {
        process.stderr.write(`${label}: the NanoMind classifier could not be fetched, and the captures are runs with it\n`);
        return 2;
      }
      if (run.status !== ex.exit) {
        exitDiffer++;
        process.stdout.write(`${label}: exited ${run.status}; docs/chooser.json declares ${ex.exit}\n`);
        continue;
      }
      const output = normalize(run.raw, normalizersFor(ex.args).map((n) => n.id), run);
      const sidecar = renderSidecar(data, item);
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
