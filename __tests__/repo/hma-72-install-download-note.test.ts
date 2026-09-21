/**
 * HMA-72 — the two documents a user reads say what a default install does.
 *
 * Installing this package runs the install script of onnxruntime-node, which
 * on Linux x64 downloads an execution-provider package from nuget.org that this
 * tool never loads. The README Install section says so and carries the two
 * switches that skip it. CHANGELOG.md corrects, exactly once and under
 * [Unreleased], the [0.27.0] claim that the script "exits before requiring
 * adm-zip on a default install", without rewriting the released entry. Both
 * texts keep the wording rules the release notes are held to.
 *
 * CHANGELOG.md is hard-wrapped, so every reading over its text collapses runs
 * of whitespace, newlines included, to a single space before comparison.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(__dirname, '..', '..');
const README = readFileSync(join(ROOT, 'README.md'), 'utf-8');
const CHANGELOG = readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf-8');
const GATE = readFileSync(join(ROOT, '__tests__', 'gate', 'no-internal-attribution.test.ts'), 'utf-8');
const LOCK = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf-8')) as {
  packages: Record<string, { dev?: boolean; hasInstallScript?: boolean }>;
};

const RETRACTION_MARKER = 'Correction to the `[0.27.0]` entry below';
const CLAIM = 'exits before requiring `adm-zip` on a default install';

/** The four released lines that must survive byte-for-byte, two leading spaces each. */
const RELEASED_LINES = [
  '  reach anyone who installs this package. The extract path carrying the advisory runs in',
  "  `onnxruntime-node`'s postinstall when it downloads execution-provider binaries; the base",
  '  package ships those binaries, so that script exits before requiring `adm-zip` on a',
  '  default install. Recorded with its reasoning and a review date in',
];

/** The body of a `## ` section, up to the next `## ` heading. */
function section(source: string, heading: string): string {
  const start = source.indexOf(heading);
  expect(start, `${heading} was not found`).toBeGreaterThan(-1);
  const rest = source.slice(start + heading.length);
  const end = rest.search(/\n## /);
  return end === -1 ? rest : rest.slice(0, end);
}

/** Every run of whitespace, newlines included, collapsed to one space. */
function collapse(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/** Non-overlapping occurrences of `needle` in `haystack`. */
function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

/**
 * Sentences of a text: split on a period outside backticks that is followed by
 * whitespace or the end, so `package-lock.json`, `install.js:22` and 1.27.0 do
 * not end a sentence.
 */
function sentences(text: string): string[] {
  const flat = collapse(text);
  const out: string[] = [];
  let current = '';
  let inCode = false;
  for (let i = 0; i < flat.length; i++) {
    const ch = flat[i];
    current += ch;
    if (ch === '`') inCode = !inCode;
    if (ch === '.' && !inCode && (i + 1 === flat.length || /\s/.test(flat[i + 1]))) {
      out.push(current.trim());
      current = '';
    }
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

/** Every regular file under `dir`, recursively. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

/** The README note: the `### ` block of the Install section that names the dependency. */
const installSection = section(README, '\n## Install\n');
const note = installSection.split(/\n### /).find((block) => block.includes('onnxruntime-node')) ?? '';

/** The retraction: the bullet carrying the marker plus its indented continuation lines. */
function retraction(): string {
  const lines = CHANGELOG.split('\n');
  const start = lines.findIndex((line) => line.includes(RETRACTION_MARKER));
  if (start === -1) return '';
  const body = [lines[start]];
  for (let i = start + 1; i < lines.length && lines[i].startsWith('  '); i++) body.push(lines[i]);
  return body.join('\n');
}

const THIRD_PARTIES = ['onnxruntime-node', 'nuget.org', 'adm-zip'];

describe('HMA-72: the README and the CHANGELOG say what a default install does', () => {
  it('HMA-72.AC1 the Install section says installing runs the onnxruntime-node install script, which on Linux x64 downloads an execution-provider package from nuget.org', () => {
    expect(note, 'no ### block of ## Install names onnxruntime-node').not.toBe('');
    const flat = collapse(note);
    for (const token of ['install script', 'onnxruntime-node', 'Linux x64', 'execution-provider package', 'nuget.org']) {
      expect(flat).toContain(token);
    }
  });

  it('HMA-72.AC1 the note says this tool requests no execution provider so the CPU provider is the only one it runs, and src/ still names none', () => {
    const flat = collapse(note);
    expect(flat).toContain('does not use that provider');
    expect(flat).toContain('requests no execution provider');
    expect(flat).toContain('CPU provider');

    const offenders = walk(join(ROOT, 'src')).filter((file) =>
      readFileSync(file, 'utf-8').includes('executionProviders'),
    );
    expect(offenders).toEqual([]);
  });

  it('HMA-72.AC1 the note carries both skip switches inline as literals', () => {
    expect(note).toContain('`ONNXRUNTIME_NODE_INSTALL=skip`');
    expect(note).toContain('`npm config set onnxruntime-node-install skip`');
  });

  it('HMA-72.AC1 the note says --ignore-scripts is safe for a CI install because exactly one non-dev dependency declares an install script, and the lockfile agrees', () => {
    const flat = collapse(note);
    expect(flat).toContain('`--ignore-scripts` is safe for a CI install of this package');
    expect(flat).toContain('exactly one non-dev dependency that declares an install script, `onnxruntime-node`');

    const withScripts = Object.entries(LOCK.packages)
      .filter(([, entry]) => entry.hasInstallScript === true && entry.dev !== true)
      .map(([name]) => name);
    expect(withScripts).toEqual(['node_modules/onnxruntime-node']);
  });

  it('HMA-72.AC2 CHANGELOG.md carries exactly one retraction of the [0.27.0] postinstall claim, under [Unreleased], quoting the claim and stating that the path runs', () => {
    expect(count(CHANGELOG, RETRACTION_MARKER)).toBe(1);
    expect(section(CHANGELOG, '\n## [Unreleased]\n')).toContain(RETRACTION_MARKER);

    const text = collapse(retraction());
    expect(text).toContain('`[0.27.0]`');
    expect(count(text, CLAIM)).toBe(1);
    expect(text).toContain('a default Linux x64 install does run the download and extraction path');

    // Whitespace-collapsed, the claim reads exactly twice in the whole file: once in the
    // released entry and once quoted in the retraction. A third reading is a second
    // retraction or a restatement; one reading is a rewritten released entry.
    expect(count(collapse(CHANGELOG), CLAIM)).toBe(2);
    expect(count(collapse(section(CHANGELOG, '\n## [0.27.0] - 2026-08-07\n')), CLAIM)).toBe(1);
  });

  it('HMA-72.AC2 the retraction names onnxruntime-node, nuget.org and adm-zip only as the object of a sentence', () => {
    const text = collapse(retraction());
    for (const name of THIRD_PARTIES) {
      expect(text).toContain(name);
      // Never the subject: no sentence opens on the name, and the name never carries a
      // finite verb of its own.
      for (const sentence of sentences(text)) {
        const opening = sentence.replace(/^[-*"`\s]+/, '');
        expect(opening.startsWith(name), `sentence opens on ${name}: ${sentence}`).toBe(false);
      }
      const asActor = new RegExp(
        `\`?${name.replace('.', '\\.')}\`?(?:'s)? (?:downloads|extracts|requires|ships|runs|declares|pins|is|was|does|has|loads)\\b`,
      );
      expect(text).not.toMatch(asActor);
    }
  });

  it('HMA-72.AC2 the released [0.27.0] entry keeps its four lines byte-for-byte', () => {
    const block = RELEASED_LINES.join('\n');
    expect(count(CHANGELOG, block)).toBe(1);
    expect(section(CHANGELOG, '\n## [0.27.0] - 2026-08-07\n')).toContain(block);
  });

  it('HMA-72.AC3 README.md is a scanned surface of the wording gate and is absent from both of its frozen baselines', () => {
    const occurrences = GATE.split('\n').filter((line) => line.includes("'README.md'"));
    expect(occurrences).toHaveLength(1);
    expect(occurrences[0].trimStart().startsWith('const SURFACES')).toBe(true);
  });

  it('HMA-72.AC3 neither text calls adm-zip 0.6.1 fixed', () => {
    for (const text of [note, retraction()]) {
      expect(text).not.toBe('');
      expect(text).not.toMatch(/\bfixed\b/i);
    }
  });

  it('HMA-72.AC3 neither text applies a severity word to onnxruntime-node, nuget.org or adm-zip', () => {
    for (const text of [note, retraction()]) {
      expect(text).not.toBe('');
      expect(text).not.toMatch(/\b(critical|high|severe|dangerous|vulnerable)\b/i);
    }
  });

  it('HMA-72.AC3 every sentence saying this tool is not affected carries the check and the date it was read, in that sentence or an adjacent one', () => {
    const notAffected = /does not use|never loads|requests no execution provider|is unchanged|not affected|is safe/i;
    const date = /\b\d{4}-\d{2}-\d{2}\b/;
    const check = /`grep -rn "executionProviders" src\/`|`"hasInstallScript": true`|`bin\/napi-v6\/linux\/x64`/;

    for (const text of [note, retraction()]) {
      const all = sentences(text);
      const flagged = all.map((sentence, i) => ({ sentence, i })).filter(({ sentence }) => notAffected.test(sentence));
      expect(flagged.length, 'no sentence of the text asserts this tool is not affected').toBeGreaterThan(0);
      for (const { sentence, i } of flagged) {
        const nearby = [all[i - 1], all[i], all[i + 1]].filter(Boolean).join(' ');
        expect(date.test(nearby), `no read date near: ${sentence}`).toBe(true);
        expect(check.test(nearby), `no check near: ${sentence}`).toBe(true);
      }
    }
  });
});
