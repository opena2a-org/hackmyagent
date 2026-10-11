/**
 * #982 — a `secure --fix` sample in the docs is in the shape `secure --fix`
 * prints.
 *
 * The scan-my-agent and OpenClaw guides showed `FIXED  CRED-001  Replaced ...`
 * rows, each over a per-file `Backup: .hackmyagent-backup/.env.1710504000`
 * line, closed by `Backups saved to .hackmyagent-backup/`. The tool prints none
 * of that: it opens the list with the `fixSummaryLine` sentence, prints one
 * `✓✓ [ID] file - name` line per fix (with an optional `→` line under it), and
 * names one timestamped run directory on a `Backup created:` line. Every fenced
 * block in the README and docs that reports fixes is held to that shape.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fixSummaryLine } from '../../src/ui/fix-summary';

const ROOT = path.resolve(__dirname, '../..');

function markdownUnder(dir: string): string[] {
  return fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true }).flatMap(entry => {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) return markdownUnder(rel);
    return entry.name.endsWith('.md') ? [rel] : [];
  }).sort();
}

const DOCS = ['README.md', ...markdownUnder('docs')];

/** A block reports fixes when it carries a line of either the old or the printed shape. */
const FIX_REPORT = /^\s*(FIXED\s+[A-Z]|Fixed \d+ issues?\b|Attempted \d+ fix|Backups? (created|saved)\b)/m;

function fixSamples(doc: string): string[] {
  const text = fs.readFileSync(path.join(ROOT, doc), 'utf8');
  return [...text.matchAll(/```[^\n]*\n([\s\S]*?)```/g)]
    .map(m => m[1])
    .filter(block => FIX_REPORT.test(block));
}

const SAMPLES = DOCS.flatMap(doc => fixSamples(doc).map((block, i) => [`${doc} #${i + 1}`, block] as const));

const SUMMARY = /^(Fixed \d+ issues?|Attempted \d+ fix)/;
const FIX_LINE = /^ {2}(✓✓|✓\?|✓) \[[A-Z][A-Z0-9]*(-[A-Z0-9]+)+\] \S.* - \S.*$/;
const FIX_DETAIL = /^ {4}→ \S/;
const BACKUP_LINE = /^Backup created: \S*\.hackmyagent-backup\/\d{4}-\d{2}-\d{2}-\d{9}-\d{3}-[0-9a-f]{8}$/;

describe('#982 secure --fix samples are in the shape the tool prints', () => {
  it('finds the fix samples in both use-case guides (non-vacuity)', () => {
    const names = SAMPLES.map(([name]) => name);
    expect(names).toContain('docs/use-cases/scan-my-agent.md #1');
    expect(names).toContain('docs/use-cases/openclaw-security.md #1');
  });

  it.each(SAMPLES)('%s', (_name, block) => {
    const lines = block.split('\n');

    expect(lines.filter(l => /^\s*FIXED\s/.test(l)), 'FIXED rows are not printed').toEqual([]);
    expect(lines.filter(l => /^\s*Backups saved to\b/.test(l)), '"Backups saved to" is not printed').toEqual([]);
    expect(
      lines.filter(l => /\.hackmyagent-backup\/[^/\s]+\.\d{9,}\b/.test(l)),
      'per-file <name>.<epoch> backups are not made',
    ).toEqual([]);

    const start = lines.findIndex(l => SUMMARY.test(l));
    expect(start, 'no "Fixed N issues" / "Attempted N fixes" line').toBeGreaterThanOrEqual(0);
    const end = lines.findIndex((l, i) => i > start && l.trim() === '');
    const list = lines.slice(start + 1, end === -1 ? undefined : end);
    const fixes = list.filter(l => !FIX_DETAIL.test(l));
    expect(fixes.length, 'no fix lines under the summary').toBeGreaterThan(0);
    for (const line of fixes) expect(line).toMatch(FIX_LINE);

    const verified = fixes.filter(l => l.startsWith('  ✓✓')).length;
    const unverified = fixes.filter(l => l.startsWith('  ✓?')).length;
    expect(lines[start]).toBe(fixSummaryLine(fixes.length, verified, unverified).text);

    const backups = lines.filter(l => l.startsWith('Backup created:'));
    expect(backups, 'one Backup created: line per run').toHaveLength(1);
    expect(backups[0]).toMatch(BACKUP_LINE);
  });
});
