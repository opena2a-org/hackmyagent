/**
 * #997: docs/SECURITY_CHECKS.md gave GIT-001 as Medium and GIT-002 as High.
 * The scanner reports both as `low` when no sensitive file is at risk and as
 * `high` when one is, so a reader comparing a scan to the catalogue saw a
 * severity the catalogue did not name, and `medium` is never reported at all.
 *
 * Each rule below scans a tree in both states and reads the catalogue entry's
 * severity line, so a severity the scanner reports and the entry does not
 * name, or one the entry names and the scanner does not report, fails here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

const SCAN_TIMEOUT = 120_000;

const ROOT = path.resolve(__dirname, '../..');
const CATALOGUE = readFileSync(path.join(ROOT, 'docs', 'SECURITY_CHECKS.md'), 'utf8');
const SEVERITY_WORDS = ['critical', 'high', 'medium', 'low', 'info'];

/** The severities the catalogue entry for `checkId` names, lower-cased. */
function documentedSeverities(checkId: string): string[] {
  const start = CATALOGUE.indexOf(`\n### ${checkId}:`);
  expect(start, `the ${checkId} entry was not found`).toBeGreaterThan(-1);
  const entry = CATALOGUE.slice(start + 1).split(/\n#/)[0];
  const line = entry.split('\n').find((l) => l.startsWith('- **Severity:**'));
  expect(line, `the ${checkId} entry has no severity line`).toBeDefined();
  const words = (line as string).toLowerCase().match(/[a-z]+/g) ?? [];
  return SEVERITY_WORDS.filter((s) => words.includes(s));
}

/** A target holding a bare package.json plus the given files. */
function target(files: Record<string, string>): string {
  const dir = tempDir('hma-git-sev-');
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }));
  for (const [name, content] of Object.entries(files)) writeFileSync(path.join(dir, name), content);
  return dir;
}

/** The severity `checkId` is reported at on a scan of `dir`. */
async function reportedSeverity(dir: string, checkId: string): Promise<string> {
  const result = await new HardeningScanner().scan({ targetDir: dir });
  const hits = (result.allFindings ?? []).filter((f) => f.checkId === checkId && !f.passed);
  expect(hits.length, `${checkId} did not fire on ${path.basename(dir)}`).toBe(1);
  return hits[0].severity;
}

const INCOMPLETE_GITIGNORE = 'node_modules/\ndist/\n';
const SECRETS_FILE = '{"note":"placeholder"}\n';

const CASES: Array<{ checkId: string; advisory: Record<string, string>; exposed: Record<string, string> }> = [
  {
    checkId: 'GIT-001',
    advisory: {},
    exposed: { 'secrets.json': SECRETS_FILE },
  },
  {
    checkId: 'GIT-002',
    advisory: { '.gitignore': INCOMPLETE_GITIGNORE },
    exposed: { '.gitignore': INCOMPLETE_GITIGNORE, 'secrets.json': SECRETS_FILE },
  },
];

describe.each(CASES)('$checkId severity in docs/SECURITY_CHECKS.md', ({ checkId, advisory, exposed }) => {
  let reported: string[];

  beforeAll(async () => {
    reported = [
      await reportedSeverity(target(advisory), checkId),
      await reportedSeverity(target(exposed), checkId),
    ];
  }, SCAN_TIMEOUT);

  it('is reported lower with no sensitive file present than with one', () => {
    expect(reported).toEqual(['low', 'high']);
  });

  it('names every severity the scanner reports, and no other', () => {
    expect(documentedSeverities(checkId).sort()).toEqual([...new Set(reported)].sort());
  });
});
