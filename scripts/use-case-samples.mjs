#!/usr/bin/env node
/**
 * The `secure` output samples in docs/use-cases/*.md that say they were
 * captured from this repository's test fixtures, regenerated from the build.
 *
 * Those blocks were pasted by hand, so they drifted as the scanner changed:
 * the insecure-mcp sample read `7 critical issues found` and `15/100` while
 * the build printed 6 and 17. Each block is now a function of the fixture and
 * the build. For every entry in SAMPLES this script copies the fixture into a
 * temporary directory of the same name, runs `node dist/cli.js` there with the
 * arguments the doc shows after `npx hackmyagent`, and renders the block:
 *
 *   - the temporary parent directory prints as `...`, so a path reads
 *     `.../insecure-mcp/mcp.json`;
 *   - the NanoMind model download notice is left out: the doc shows a run with
 *     the classifier already cached, and the scan seeds that cache from
 *     ~/.nanomind/models when it holds the pinned files (the CLI re-checks
 *     every file's sha256, so a stale copy is fetched again);
 *   - every "Why ..." explainer inside a finding box becomes `│ ...`;
 *   - with `findings`, every finding box with another title becomes `...`,
 *     one marker for each run of consecutive cut boxes;
 *   - with `cut`, everything between the `after` line and the `before` line
 *     becomes `...`;
 *   - trailing spaces are removed.
 *
 * The block a sample owns is the first plain fenced block after the ```bash
 * block whose body is `npx hackmyagent <args>`.
 *
 * Usage (after `npm run build`):
 *   node scripts/use-case-samples.mjs           compare every block with a fresh capture
 *   node scripts/use-case-samples.mjs --write   rewrite every block from a fresh capture
 *
 * The comparison ignores the version on the `Scanned with hackmyagent v...`
 * line, so a version bump alone is not drift; `--write` updates that line too.
 *
 * Exit codes: 0 every block matches (or was written), 1 a block differs from
 * the build, 2 nothing could be compared (no build, classifier unavailable,
 * a sample's anchor not found).
 */
import { spawnSync } from 'node:child_process';
import {
  copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, closeSync,
  readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
export const USE_CASES = path.join(REPO_ROOT, 'docs', 'use-cases');

/** One documented capture: the doc, the fixture, the arguments, and the trims the doc applies. */
export const SAMPLES = [
  {
    doc: 'docs/use-cases/scan-my-agent.md',
    fixture: 'insecure-library',
    args: ['secure'],
  },
  {
    doc: 'docs/use-cases/scan-my-agent.md',
    fixture: 'insecure-library',
    args: ['secure', '--fix', '--dry-run'],
    cut: { after: /^ {2}Security {2}━/, before: /^ {2}Dry run complete:/ },
  },
  {
    doc: 'docs/use-cases/red-team-mcp.md',
    fixture: 'insecure-mcp',
    args: ['secure'],
    // "trimmed to the MCP findings"
    findings: [
      'Unrestricted Shell Server',
      'MCP Root Filesystem Access',
      'Wildcard Tool Access',
      'Sensitive MCP Tools',
      'MCP Request Timeout',
    ],
  },
  {
    doc: 'docs/use-cases/openclaw-security.md',
    fixture: 'insecure-openclaw',
    args: ['secure'],
  },
  {
    doc: 'docs/use-cases/openclaw-security.md',
    fixture: 'insecure-openclaw',
    args: ['secure', '--fix', '--dry-run'],
    cut: { after: /^ {2}Security {2}━/, before: /^ {2}Dry run complete:/ },
  },
];

const BOX_HEAD = /^ {2}│ (CRITICAL|HIGH|MEDIUM|LOW|INFO) {2}(.+)$/;
const EXPLAINER_HEAD = /^ {2}│ ━━ Why .+ ━━/;
const DOWNLOAD_NOTICE = [
  /^NanoMind: downloading the classifier model /,
  /^ {2}This happens once per cache;/,
  /^NanoMind: model downloaded and verified /,
];
const DOWNLOAD_FAILED = /^NanoMind: model download failed/;
const VERSION_LINE = /^( {2}Scanned with hackmyagent v)\S+$/;

/** Every fenced block in `text`, with the offsets of its body. */
function fences(text) {
  return [...text.matchAll(/```([^\n]*)\n([\s\S]*?)```/g)].map(m => {
    const bodyStart = m.index + 3 + m[1].length + 1;
    return { info: m[1].trim(), body: m[2], bodyStart, bodyEnd: bodyStart + m[2].length };
  });
}

function bodyLines(body) {
  return body.replace(/\n$/, '').split('\n');
}

/** The output block a sample owns in `text`, or null. */
export function findSampleBlock(text, sample) {
  const command = ['npx hackmyagent', ...sample.args].join(' ');
  const blocks = fences(text);
  const at = blocks.findIndex(b => b.info === 'bash' && b.body.trim() === command);
  const next = at === -1 ? undefined : blocks.slice(at + 1).find(b => b.info === '');
  return next ? { bodyStart: next.bodyStart, bodyEnd: next.bodyEnd, lines: bodyLines(next.body) } : null;
}

/**
 * Every plain fenced block in docs/use-cases that presents itself as a capture
 * of a fixture scan (its first line is `Scanning .../`), as `doc@offset`.
 */
export function capturedBlocks() {
  return readdirSync(USE_CASES).filter(f => f.endsWith('.md')).sort().flatMap(f => {
    const doc = `docs/use-cases/${f}`;
    return fences(readFileSync(path.join(REPO_ROOT, doc), 'utf8'))
      .filter(b => b.info === '' && /^Scanning \.\.\.\//.test(b.body))
      .map(b => `${doc}@${b.bodyStart}`);
  });
}

/** The same key for the block a sample owns, or null when the doc has none. */
export function sampleBlockKey(sample) {
  const block = findSampleBlock(readFileSync(path.join(REPO_ROOT, sample.doc), 'utf8'), sample);
  return block ? `${sample.doc}@${block.bodyStart}` : null;
}

/** Copy the pinned classifier files into `home` when ~/.nanomind/models holds all of them. */
export function seedClassifier(home, sourceHome = os.homedir()) {
  const require = createRequire(import.meta.url);
  const { MODEL_FILES } = require(path.join(REPO_ROOT, 'dist', 'nanomind-core', 'inference', 'tme-classifier.js'));
  const from = path.join(sourceHome, '.nanomind', 'models');
  const ready = MODEL_FILES.every(f => {
    try { return statSync(path.join(from, f.name)).size === f.bytes; } catch { return false; }
  });
  if (!ready) return false;
  const to = path.join(home, '.nanomind', 'models');
  mkdirSync(to, { recursive: true });
  for (const f of MODEL_FILES) copyFileSync(path.join(from, f.name), path.join(to, f.name));
  return true;
}

/**
 * Run a sample against a fresh copy of its fixture. `home` is the HOME the
 * CLI runs with; pass one HOME to every capture so the classifier is fetched
 * at most once. stdout and stderr share one file, so their lines keep the
 * order the CLI wrote them in.
 */
export function captureSample(sample, { home, cli = CLI, timeoutMs = 150_000 }) {
  const parent = mkdtempSync(path.join(os.tmpdir(), 'hma-use-case-'));
  try {
    const dir = path.join(parent, sample.fixture);
    cpSync(path.join(REPO_ROOT, 'test-fixtures', sample.fixture), dir, { recursive: true });
    const out = path.join(parent, 'output.txt');
    const fd = openSync(out, 'w');
    let r;
    try {
      r = spawnSync(process.execPath, [cli, ...sample.args], {
        cwd: dir,
        stdio: ['ignore', fd, fd],
        timeout: timeoutMs,
        env: {
          PATH: process.env.PATH ?? '',
          HOME: home,
          TMPDIR: os.tmpdir(),
          LANG: 'en_US.UTF-8',
          NO_COLOR: '1',
          OPENA2A_TELEMETRY: 'off',
          // The classifier download honours the proxy settings.
          ...Object.fromEntries(['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'NO_PROXY', 'no_proxy']
            .filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]])),
        },
      });
    } finally {
      closeSync(fd);
    }
    if (r.error || r.status === null) {
      throw new Error(`${sample.args.join(' ')} on ${sample.fixture} did not finish: ${r.error?.message ?? r.signal}`);
    }
    let text = readFileSync(out, 'utf8');
    // Longest first: on macOS the temp parent `/var/...` is a suffix of its
    // real path `/private/var/...`, and replacing it first leaves `/private...`.
    const parents = [...new Set([parent, realpathSync(parent)])].sort((a, b) => b.length - a.length);
    for (const p of parents) text = text.split(`${p}${path.sep}`).join('.../');
    const lines = text.split('\n');
    return {
      status: r.status,
      classifier: !lines.some(l => DOWNLOAD_FAILED.test(l)),
      lines: lines.filter(l => !DOWNLOAD_NOTICE.some(re => re.test(l))),
    };
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
}

/** Finding boxes: a severity head line and the `  │` lines under it. */
function findingBoxes(lines) {
  const boxes = [];
  for (let i = 0; i < lines.length; i++) {
    const m = BOX_HEAD.exec(lines[i]);
    if (!m) continue;
    let end = i + 1;
    while (end < lines.length && lines[end].startsWith('  │')) end++;
    boxes.push({ start: i, end, title: m[2] });
    i = end - 1;
  }
  return boxes;
}

function keepFindings(lines, titles) {
  const boxes = findingBoxes(lines);
  const missing = titles.filter(t => !boxes.some(b => b.title === t));
  if (missing.length) throw new Error(`no finding box titled ${missing.map(t => `"${t}"`).join(', ')}`);
  const out = [];
  let at = 0;
  for (let k = 0; k < boxes.length; k++) {
    if (titles.includes(boxes[k].title)) continue;
    const first = boxes[k];
    // Cut boxes separated by one blank line share a marker.
    while (k + 1 < boxes.length && !titles.includes(boxes[k + 1].title) && boxes[k + 1].start === boxes[k].end + 1) k++;
    out.push(...lines.slice(at, first.start), '  ...');
    at = boxes[k].end;
  }
  return [...out, ...lines.slice(at)];
}

function cutExplainers(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!EXPLAINER_HEAD.test(lines[i])) {
      out.push(lines[i]);
      continue;
    }
    if (out[out.length - 1] === '  │') out.pop();
    out.push('  │ ...');
    while (i + 1 < lines.length && lines[i + 1].startsWith('  │')) i++;
  }
  return out;
}

function cutRange(lines, { after, before }) {
  const a = lines.findIndex(l => after.test(l));
  const b = a === -1 ? -1 : lines.findIndex((l, i) => i > a && before.test(l));
  if (b === -1) throw new Error(`no lines matching ${after} then ${before}`);
  return [...lines.slice(0, a + 1), '', '  ...', '', ...lines.slice(b)];
}

/** The block a sample's doc should hold, from a capture's lines. */
export function renderSample(sample, captured) {
  let lines = captured.map(l => l.replace(/\s+$/, ''));
  while (lines.length && lines[0] === '') lines.shift();
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (sample.findings) lines = keepFindings(lines, sample.findings);
  lines = cutExplainers(lines);
  if (sample.cut) lines = cutRange(lines, sample.cut);
  return lines;
}

const versionless = lines => lines.map(l => l.replace(VERSION_LINE, '$1<version>'));

/**
 * null when `documented` matches `rendered` apart from the scanned-with
 * version; otherwise the first differing line, 1-based within the block.
 */
export function compareBlock(documented, rendered) {
  const a = versionless(documented);
  const b = versionless(rendered);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) return { line: i + 1, documented: documented[i], built: rendered[i] };
  }
  return null;
}

function main() {
  const args = process.argv.slice(2);
  const write = args.includes('--write');
  const unknown = args.filter(a => a !== '--write');
  if (unknown.length) {
    process.stderr.write(`unknown argument "${unknown[0]}"\nusage: node scripts/use-case-samples.mjs [--write]\n`);
    return 2;
  }
  if (!existsSync(CLI)) {
    process.stderr.write('dist/cli.js is missing; run `npm run build` first\n');
    return 2;
  }
  const home = mkdtempSync(path.join(os.tmpdir(), 'hma-use-case-home-'));
  let drift = 0;
  try {
    seedClassifier(home);
    for (const sample of SAMPLES) {
      const label = `${sample.doc}: npx hackmyagent ${sample.args.join(' ')}`;
      const docPath = path.join(REPO_ROOT, sample.doc);
      const text = readFileSync(docPath, 'utf8');
      const block = findSampleBlock(text, sample);
      if (!block) {
        process.stderr.write(`${label}: no output block after that command\n`);
        return 2;
      }
      const capture = captureSample(sample, { home });
      if (!capture.classifier) {
        process.stderr.write(`${label}: the NanoMind classifier could not be fetched, and the samples are captures with it\n`);
        return 2;
      }
      const rendered = renderSample(sample, capture.lines);
      const diff = compareBlock(block.lines, rendered);
      if (write) {
        writeFileSync(docPath, text.slice(0, block.bodyStart) + rendered.join('\n') + '\n' + text.slice(block.bodyEnd));
        process.stdout.write(`${label}: written\n`);
      } else if (diff) {
        drift++;
        process.stdout.write(`${label}: differs at block line ${diff.line}\n  doc:   ${diff.documented ?? '(none)'}\n  build: ${diff.built ?? '(none)'}\n`);
      } else {
        process.stdout.write(`${label}: matches\n`);
      }
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
  if (drift) process.stdout.write(`${drift} block(s) differ from the build. Regenerate: node scripts/use-case-samples.mjs --write\n`);
  return drift ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.exit(main());
  } catch (err) {
    process.stderr.write(`use-case samples failed: ${err.stack ?? err.message}\n`);
    process.exit(2);
  }
}
