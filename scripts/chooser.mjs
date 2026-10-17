#!/usr/bin/env node
/**
 * The README section "What do you want to check?", rendered from
 * docs/chooser.json.
 *
 * The data file holds, for each thing a reader may want to check, the wording
 * of the choice (`ask`), the command to run (`run`), what its exit code 1
 * means (`findingMeans`), and the command to run next (`next`, with an
 * optional `nextWhen`). `options` are the common jobs, in the order a reader
 * sees them; `more` holds the commands for narrower jobs, with no next command.
 *
 * README.md carries the rendering between a `<!-- chooser:start` line and a
 * `<!-- chooser:end -->` line, so the README and the data cannot drift apart:
 * an edit goes to the data file, and `--write` regenerates the section. The
 * README shows each choice, its command and its next command. It leaves
 * `findingMeans` out to hold the README's length: the exit codes are listed in
 * docs/commands.md, which the README links. `findingMeans` is for a surface
 * that shows one answer at a time.
 *
 * Usage:
 *   node scripts/chooser.mjs --check [--readme <file>]   compare the section with the data
 *   node scripts/chooser.mjs --write [--readme <file>]   rewrite the section from the data
 *
 * Exit codes: 0 the section matches the data (or was written), 1 the section
 * differs from the data, 2 nothing could be compared (the data cannot be read
 * or is invalid, a marker is missing or repeated, an unknown argument).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DATA = path.join(REPO_ROOT, 'docs', 'chooser.json');
export const README = path.join(REPO_ROOT, 'README.md');

const START_PREFIX = '<!-- chooser:start';
export const START = `${START_PREFIX} docs/chooser.json -->`;
export const END = '<!-- chooser:end -->';

const ID = /^[a-z][a-z0-9-]*$/;

/** One-line text that renders as prose: no newline, and no backtick that would open a code span. */
function isText(value) {
  return typeof value === 'string' && value.trim() === value && value.length > 0 && !/[\n\r`]/.test(value);
}

/** Every problem with the data file, as `field: reason`; empty when it can be rendered. */
export function validateChooser(data) {
  const problems = [];
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return ['the file does not hold a JSON object'];
  if (!isText(data.question)) problems.push('question: missing or not one line of text');
  if (!isText(data.invocation)) problems.push('invocation: missing or not one line of text');
  if (!Array.isArray(data.options) || data.options.length === 0) problems.push('options: missing or empty');
  if (!Array.isArray(data.more)) problems.push('more: missing or not a list');
  const seen = new Set();
  const entries = [
    ...(Array.isArray(data.options) ? data.options.map((entry, i) => ({ entry, at: `options[${i}]`, needsNext: true })) : []),
    ...(Array.isArray(data.more) ? data.more.map((entry, i) => ({ entry, at: `more[${i}]`, needsNext: false })) : []),
  ];
  for (const { entry, at, needsNext } of entries) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      problems.push(`${at}: not an object`);
      continue;
    }
    if (typeof entry.id !== 'string' || !ID.test(entry.id)) problems.push(`${at}.id: missing or not lower-case words joined by hyphens`);
    else if (seen.has(entry.id)) problems.push(`${at}.id: "${entry.id}" is used twice`);
    else seen.add(entry.id);
    for (const field of ['ask', 'run', 'findingMeans']) {
      if (!isText(entry[field])) problems.push(`${at}.${field}: missing or not one line of text`);
    }
    if (needsNext && !isText(entry.next)) problems.push(`${at}.next: missing or not one line of text`);
    if (!needsNext && entry.next !== undefined) problems.push(`${at}.next: an entry under more has no next command`);
    if (entry.nextWhen !== undefined && (!needsNext || !isText(entry.nextWhen))) {
      problems.push(`${at}.nextWhen: only an entry under options has one, and it is one line of text`);
    }
  }
  return problems;
}

/** The full command line a reader copies for the arguments `args`. */
export function commandLine(data, args) {
  return `${data.invocation} ${args}`;
}

/** Every command the data names, with where it is named: each option's run and next, each more entry's run. */
export function commands(data) {
  return [
    ...data.options.flatMap((o) => [
      { at: `${o.id}.run`, args: o.run },
      { at: `${o.id}.next`, args: o.next },
    ]),
    ...data.more.map((m) => ({ at: `${m.id}.run`, args: m.run })),
  ];
}

/** The README section, both marker lines included, with no trailing newline. */
export function renderSection(data) {
  const code = (args) => `\`${commandLine(data, args)}\``;
  const lines = [START, `## ${data.question}`, ''];
  for (const o of data.options) {
    const next = o.nextWhen ? `Next, ${o.nextWhen}: ${code(o.next)}.` : `Next: ${code(o.next)}.`;
    lines.push(`- **${o.ask}:** ${code(o.run)}. ${next}`);
  }
  if (data.more.length > 0) {
    lines.push(`- **More.** ${data.more.map((m) => `${m.ask}: ${code(m.run)}.`).join(' ')}`);
  }
  lines.push(END);
  return lines.join('\n');
}

/**
 * Where the section sits in `readme`: 0-based line indices of the two
 * markers. `problem` is set instead when a marker is missing, repeated or the
 * end comes first.
 */
export function locateSection(readme) {
  const lines = readme.split('\n');
  const starts = lines.flatMap((l, i) => (l.startsWith(START_PREFIX) ? [i] : []));
  const ends = lines.flatMap((l, i) => (l === END ? [i] : []));
  if (starts.length !== 1) return { problem: `${starts.length} lines start with "${START_PREFIX}"; the README needs exactly one` };
  if (ends.length !== 1) return { problem: `${ends.length} lines read "${END}"; the README needs exactly one` };
  if (ends[0] < starts[0]) return { problem: `"${END}" comes before the start marker` };
  return { start: starts[0], end: ends[0], text: lines.slice(starts[0], ends[0] + 1).join('\n') };
}

/** `readme` with the located section replaced by `rendered`. */
export function replaceSection(readme, location, rendered) {
  const lines = readme.split('\n');
  return [...lines.slice(0, location.start), rendered, ...lines.slice(location.end + 1)].join('\n');
}

function main(argv) {
  let mode = null;
  let readmePath = README;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if ((arg === '--check' || arg === '--write') && mode === null) mode = arg.slice(2);
    else if (arg === '--readme' && i + 1 < argv.length) readmePath = path.resolve(argv[++i]);
    else {
      process.stderr.write(`chooser: unexpected argument "${arg}"\nUsage: node scripts/chooser.mjs --check|--write [--readme <file>]\n`);
      return 2;
    }
  }
  if (mode === null) {
    process.stderr.write('Usage: node scripts/chooser.mjs --check|--write [--readme <file>]\n');
    return 2;
  }
  const dataName = path.relative(REPO_ROOT, DATA);
  let data;
  try {
    data = JSON.parse(readFileSync(DATA, 'utf8'));
  } catch (err) {
    process.stderr.write(`chooser: cannot read ${dataName}: ${err.message}\n`);
    return 2;
  }
  const problems = validateChooser(data);
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`chooser: ${dataName}: ${p}\n`);
    return 2;
  }
  let readme;
  try {
    readme = readFileSync(readmePath, 'utf8');
  } catch (err) {
    process.stderr.write(`chooser: cannot read ${readmePath}: ${err.message}\n`);
    return 2;
  }
  const location = locateSection(readme);
  if (location.problem) {
    process.stderr.write(`chooser: ${readmePath}: ${location.problem}\n`);
    return 2;
  }
  const rendered = renderSection(data);
  if (mode === 'write') {
    if (location.text !== rendered) writeFileSync(readmePath, replaceSection(readme, location, rendered));
    process.stdout.write(`chooser: ${readmePath}: section written from ${dataName}\n`);
    return 0;
  }
  if (location.text === rendered) {
    process.stdout.write(`chooser: ${readmePath}: section matches ${dataName}\n`);
    return 0;
  }
  const have = location.text.split('\n');
  const want = rendered.split('\n');
  let k = 0;
  while (k < have.length && have[k] === want[k]) k++;
  process.stdout.write(
    `chooser: ${readmePath}:${location.start + k + 1}: the section differs from ${dataName}\n` +
      `  README: ${have[k] ?? '(none)'}\n  data:   ${want[k] ?? '(none)'}\n` +
      'Regenerate: node scripts/chooser.mjs --write\n',
  );
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
