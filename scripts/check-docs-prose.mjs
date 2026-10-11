#!/usr/bin/env node
/**
 * Prose check for the Markdown a reader outside the tool sees.
 *
 * Two rules, applied to every tracked `.md` and `.mdx` file in scope:
 *
 *   1. No dash written as a spaced double hyphen (` -- `), an em dash (U+2014)
 *      or a spaced en dash (U+2013). A sentence uses a period, a comma, a colon
 *      or parentheses instead.
 *   2. No heading or section named "Why this exists" or "Why this matters",
 *      including the forms with a noun between ("Why this playbook exists").
 *
 * Only prose is read. Front matter, fenced code blocks, indented code blocks,
 * HTML comments and inline code spans are skipped: inside a command, `--` is an
 * option prefix or the end-of-options separator, not a dash. A table delimiter
 * row and a line of hyphens alone are markup, not prose.
 *
 * Out of scope, by path: CHANGELOG.md and the fragments in changelog.d/
 * (released history is not rewritten; changelog.d/README.md is in scope),
 * LICENSE files, dependency and build output, and every test, fixture, corpus,
 * golden, snapshot or example directory, whose text is data a test compares
 * against.
 *
 *   node scripts/check-docs-prose.mjs           every tracked file in scope
 *   node scripts/check-docs-prose.mjs <file>... the named files, in scope or not
 *
 * Exit 0 when every file passes, 1 with one `file:line: reason` per hit, and
 * 2 when the file list cannot be read or a named file does not exist.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Directory names whose Markdown is data, output or a dependency rather than documentation. */
const EXCLUDED_DIR = /^(?:node_modules|vendor|dist|build|__tests__|tests?|test-[\w.-]+|[\w.-]*fixtures?|corpus|golden|__snapshots__|snapshots?|examples?)$/i;

/** True when a repository-relative path is held to the prose rules. */
export function inScope(relPath) {
  const parts = relPath.split('/');
  const base = parts[parts.length - 1];
  if (!/\.mdx?$/i.test(base)) return false;
  if (base === 'CHANGELOG.md') return false;
  if (/^LICENSE/i.test(base)) return false;
  if (parts.slice(0, -1).some((dir) => EXCLUDED_DIR.test(dir))) return false;
  const changelogDir = parts.indexOf('changelog.d');
  if (changelogDir !== -1 && !(changelogDir === parts.length - 2 && base === 'README.md')) return false;
  return true;
}

/**
 * Tracked Markdown files in scope, repository-relative. Every GIT_ variable is
 * dropped first: a GIT_DIR exported by a hook would otherwise point the
 * listing at another repository.
 */
export function trackedFiles(root = REPO_ROOT) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')));
  const run = spawnSync('git', ['-C', root, 'ls-files', '-z', '--', '*.md', '*.mdx'], { encoding: 'utf8', env });
  if (run.status !== 0) {
    throw new Error(`git ls-files failed in ${root}: ${(run.stderr || '').trim() || `exit ${run.status}`}`);
  }
  return run.stdout.split('\0').filter((p) => p && inScope(p)).sort();
}

/** Index of the next run of exactly `n` backticks at or after `from`, or -1. */
function closingRun(text, from, n) {
  let j = from;
  while (j < text.length) {
    if (text[j] !== '`') {
      j += 1;
      continue;
    }
    let m = 0;
    while (text[j + m] === '`') m += 1;
    if (m === n) return j;
    j += m;
  }
  return -1;
}

const masked = (s) => s.replace(/[^\n]/g, 'x');

/**
 * Mask the inline code spans and HTML comments in one block of Markdown,
 * keeping every line break so the result splits back into the same lines.
 * A span opened by N backticks closes at the next run of exactly N, which may
 * sit on a later line of the same block; an unclosed run is literal text. A
 * comment may run past the block, so its state is carried in `state`. The
 * mask character is not a space, so `a`--`b` cannot turn into a spaced double
 * hyphen once the spans are gone.
 */
export function maskBlock(text, state = { inComment: false }) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    if (state.inComment) {
      const end = text.indexOf('-->', i);
      const stop = end === -1 ? text.length : end + 3;
      out += masked(text.slice(i, stop));
      i = stop;
      if (end !== -1) state.inComment = false;
      continue;
    }
    if (text.startsWith('<!--', i)) {
      state.inComment = true;
      out += 'xxxx';
      i += 4;
      continue;
    }
    if (text[i] === '`') {
      let n = 0;
      while (text[i + n] === '`') n += 1;
      const close = closingRun(text, i + n, n);
      const stop = close === -1 ? i + n : close + n;
      out += close === -1 ? text.slice(i, stop) : masked(text.slice(i, stop));
      i = stop;
      continue;
    }
    out += text[i];
    i += 1;
  }
  return out;
}

const FENCE_OPEN = /^\s*(?:>\s*)*(`{3,}|~{3,})/;
const SINGLE_LINE_BLOCK = /^\s{0,3}(?:#{1,6}(?:\s|$)|\|)/;
const HYPHEN_RULE = /^\s*-+\s*$/;
const LIST_ITEM = /^([ \t]*)([-*+]|\d{1,9}[.)])(?:([ \t]+)|$)/;
const TABLE_CELL = /^:?-+:?$/;

/**
 * A table delimiter row: cells of hyphens, each with an optional colon at
 * either end, split by `|`, with optional outer pipes.
 *
 * A function rather than one regular expression: the expression's optional
 * spaces after a cell and before the closing pipe overlapped, so a hyphen
 * followed by many spaces and any other character backtracked quadratically
 * (2.8 s at 80,000 spaces, 45.6 s at 320,000).
 */
function isTableDelimiter(line) {
  let body = line.trim();
  if (body.startsWith('|')) body = body.slice(1);
  if (body.endsWith('|')) body = body.slice(0, -1);
  return body.split('|').every((cell) => TABLE_CELL.test(cell.trim()));
}

/** Columns of leading whitespace, a tab advancing to the next multiple of four. */
function indentOf(line) {
  let col = 0;
  for (const ch of line) {
    if (ch === ' ') col += 1;
    else if (ch === '\t') col += 4 - (col % 4);
    else break;
  }
  return col;
}

/**
 * The column a list item's content starts at: after the marker and the spaces
 * that follow it, or one column after the marker when five or more follow
 * (those lines open an indented code block inside the item).
 */
function listContentIndent(match) {
  const markerEnd = indentOf(match[1]) + match[2].length;
  const gap = match[3] ? indentOf(' '.repeat(markerEnd) + match[3]) - markerEnd : 1;
  return markerEnd + (gap > 4 ? 1 : gap);
}
const WHY_HEADING = /^\s{0,3}(?:#{1,6}\s+|(?:\*\*|__)\s*|<h[1-6][^>]*>\s*)why this(?:\s+[\w.-]+){0,3}\s+(?:exists|matters)\b/i;
const DASHES = [
  { re: /—/, reason: 'em dash (U+2014) in prose' },
  { re: /(?:^|\s)–(?:\s|$)/, reason: 'spaced en dash (U+2013) in prose' },
  { re: /(?:^|\s)--(?:\s|$)/, reason: 'spaced double hyphen used as a dash in prose' },
];

/**
 * The prose of each line, with code and comments masked, or null for a line
 * that carries no prose (front matter, a fenced or indented code block, a
 * blank line).
 *
 * An indented code block is a line indented four columns past its container,
 * the document or the list item it sits in, that does not continue a
 * paragraph; it runs until a non-blank line indented less. Inside a list item
 * a line indented to the item's content is a paragraph of that item, so the
 * open list items are tracked by the column their content starts at.
 */
export function proseLines(text) {
  const lines = text.split(/\r?\n/);
  const out = new Array(lines.length).fill(null);
  let first = 0;
  if (lines[0] === '---') {
    const end = lines.findIndex((l, idx) => idx > 0 && (l === '---' || l === '...'));
    if (end !== -1) first = end + 1;
  }
  const state = { inComment: false };
  let fence = null;
  let indentedCode = null;
  const lists = [];
  let block = [];
  const flush = () => {
    if (!block.length) return;
    const masks = maskBlock(block.map((idx) => lines[idx]).join('\n'), state).split('\n');
    block.forEach((idx, k) => {
      out[idx] = masks[k];
    });
    block = [];
  };
  for (let idx = first; idx < lines.length; idx += 1) {
    const raw = lines[idx];
    if (fence) {
      const close = raw.match(FENCE_OPEN);
      if (close && close[1][0] === fence[0] && close[1].length >= fence.length && raw.trim().replace(/^(?:>\s*)*/, '') === close[1]) fence = null;
      continue;
    }
    if (indentedCode !== null) {
      if (!raw.trim() || indentOf(raw) >= indentedCode) continue;
      indentedCode = null;
    }
    if (!state.inComment && raw.trim() && (!block.length || SINGLE_LINE_BLOCK.test(raw))) {
      // A line that starts a block closes every list item it is not indented into.
      const indent = indentOf(raw);
      while (lists.length && indent < lists[lists.length - 1]) lists.pop();
      const codeAt = (lists.length ? lists[lists.length - 1] : 0) + 4;
      if (!block.length && indent >= codeAt) {
        indentedCode = codeAt;
        continue;
      }
    }
    const item = state.inComment ? null : raw.match(LIST_ITEM);
    if (item) {
      const markerAt = indentOf(item[1]);
      while (lists.length && lists[lists.length - 1] > markerAt) lists.pop();
      lists.push(listContentIndent(item));
    }
    if (!state.inComment && FENCE_OPEN.test(raw)) {
      flush();
      fence = raw.match(FENCE_OPEN)[1];
      continue;
    }
    if (!raw.trim()) {
      flush();
      continue;
    }
    if (SINGLE_LINE_BLOCK.test(raw)) {
      flush();
      block.push(idx);
      flush();
      continue;
    }
    block.push(idx);
  }
  flush();
  return out;
}

/** Every rule hit in one Markdown text, as `{ line, reason }` with 1-based lines. */
export function checkText(text) {
  const hits = [];
  proseLines(text).forEach((line, idx) => {
    if (line === null || !line.trim() || isTableDelimiter(line) || HYPHEN_RULE.test(line)) return;
    if (WHY_HEADING.test(line)) hits.push({ line: idx + 1, reason: 'heading or section named "Why this exists/matters"' });
    for (const { re, reason } of DASHES) {
      if (re.test(line)) hits.push({ line: idx + 1, reason });
    }
  });
  return hits;
}

/** Hits for each file, as `file:line: reason` strings. */
export function checkFiles(relPaths, root = REPO_ROOT) {
  const out = [];
  for (const rel of relPaths) {
    const abs = path.resolve(root, rel);
    if (!existsSync(abs)) continue;
    for (const hit of checkText(readFileSync(abs, 'utf8'))) out.push(`${rel}:${hit.line}: ${hit.reason}`);
  }
  return out;
}

function main(argv) {
  let files;
  try {
    // A tracked file deleted from the working tree is no longer a page anyone
    // reads; a named file that does not exist is a mistake in the command.
    files = argv.length
      ? argv.map((p) => path.relative(REPO_ROOT, path.resolve(p)))
      : trackedFiles().filter((rel) => existsSync(path.resolve(REPO_ROOT, rel)));
  } catch (err) {
    process.stderr.write(`docs prose check: ${err.message}\n`);
    return 2;
  }
  const missing = argv.filter((p) => !existsSync(path.resolve(p)));
  if (missing.length) {
    for (const p of missing) process.stderr.write(`docs prose check: ${p}: no such file\n`);
    return 2;
  }
  const hits = checkFiles(files);
  if (hits.length) {
    for (const h of hits) process.stderr.write(`${h}\n`);
    process.stderr.write(
      `docs prose check: ${hits.length} hit(s) in ${files.length} file(s). Rewrite each dash as a period, comma, colon or parentheses, and fold or drop each "Why this exists/matters" section.\n`,
    );
    return 1;
  }
  process.stdout.write(`docs prose check: ${files.length} file(s), no dash or "Why this exists/matters" heading in prose.\n`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
