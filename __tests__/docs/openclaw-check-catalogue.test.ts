/**
 * #978: the OpenClaw tables in docs/SECURITY_CHECKS.md describe the checks
 * the scanner reports under each id.
 *
 * The tables were written against an earlier plan of the checks and never
 * followed the scanner: 29 of the 47 rows they had then named a different
 * check (GATEWAY-002 was catalogued as "Open gateway port" while the scanner
 * reports it as "Missing WebSocket Origin Validation"), and 6 of the 9
 * auto-fix rows were ids that `--fix` cannot change. This suite reads every
 * emission site of a documented id, in src/hardening/scanner.ts and in the
 * capability validator it calls for SKILL-018, and holds each row's name,
 * severity and fixability to them, and the auto-fix table to the rows marked
 * fixable.
 *
 * A row's Description opens with the check name, then `: ` and a summary. A
 * name that itself holds a colon (the CVE checks) ends with `. ` instead.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');
const DOC = fs.readFileSync(path.join(ROOT, 'docs/SECURITY_CHECKS.md'), 'utf8');
/** The scanner, and the helper file whose findings its OpenClaw checks push. */
const SOURCES = ['src/hardening/scanner.ts', 'src/hardening/skill-capability-validator.ts']
  .map(file => fs.readFileSync(path.join(ROOT, file), 'utf8'));

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

interface Site {
  name: string;
  severities: string[];
  fixable: boolean;
}

/** The object literal around index `at`, from its `{` to the matching `}`. */
function enclosingObject(source: string, at: number): string {
  const start = source.lastIndexOf('{', at);
  let depth = 0;
  for (let i = start; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error(`unbalanced object at offset ${at}`);
}

/**
 * Severities a site can report: a literal, or the two arms of the
 * `const x = cond ? 'a' : 'b'` the site's `severity` refers to.
 */
function siteSeverities(source: string, at: number, object: string): string[] {
  const literal = /\bseverity:\s*'(\w+)'/.exec(object);
  if (literal) return [literal[1]];
  const ref = /\bseverity(?::\s*(\w+))?\s*,/.exec(object);
  if (!ref) throw new Error(`no severity in ${object.slice(0, 80)}`);
  const ident = ref[1] ?? 'severity';
  const decl = new RegExp(`const\\s+${ident}\\b[^=;]*=\\s*[^;?]*\\?\\s*'(\\w+)'\\s*:\\s*'(\\w+)'\\s*;`, 'g');
  let last: RegExpExecArray | null = null;
  for (const m of source.slice(0, at).matchAll(decl)) last = m as RegExpExecArray;
  if (!last) throw new Error(`cannot resolve severity identifier ${ident}`);
  return [last[1], last[2]];
}

function scannerSites(id: string): Site[] {
  const sites: Site[] = [];
  for (const source of SOURCES) {
    for (const m of source.matchAll(new RegExp(`checkId:\\s*'${id}'`, 'g'))) {
      const object = enclosingObject(source, m.index!);
      const name = /\bname:\s*'([^']+)'/.exec(object);
      const fixable = /\bfixable:\s*(true|false)/.exec(object);
      if (!name || !fixable) throw new Error(`incomplete finding for ${id}`);
      sites.push({
        name: name[1],
        severities: siteSeverities(source, m.index!, object),
        fixable: fixable[1] === 'true',
      });
    }
  }
  return sites;
}

/** True when a row's Description opens with `name`, closed by `: ` or `. `. */
function opensWithName(description: string, name: string): boolean {
  const text = description.toLowerCase();
  const lead = name.toLowerCase();
  return text === lead || text.startsWith(`${lead}: `) || text.startsWith(`${lead}. `);
}

const section = (() => {
  const start = DOC.indexOf('\n## OpenClaw Security Checks');
  expect(start, 'OpenClaw section not found').toBeGreaterThan(-1);
  const end = DOC.indexOf('\n## ', start + 1);
  return DOC.slice(start, end === -1 ? undefined : end);
})();
const autoFixAt = section.indexOf('\n### Auto-Fix Capabilities');

const ID = '(?:SKILL|HEARTBEAT|GATEWAY|CONFIG|SUPPLY|CVE)-\\d{3}';
const checkRows = [...section.slice(0, autoFixAt).matchAll(
  new RegExp(`^\\| (${ID}) \\| ([^|]+?) \\| (Yes|No) \\| ([^|]+?) \\|$`, 'gm'),
)].map(m => ({ id: m[1], severity: m[2], fixable: m[3] === 'Yes', description: m[4] }));
const autoFixIds = [...section.slice(autoFixAt).matchAll(new RegExp(`^\\| (${ID}) \\|`, 'gm'))].map(m => m[1]);
/** Every line that opens a check row, whether or not its four cells parse. */
const checkRowLines = [...section.slice(0, autoFixAt).matchAll(/^\| [A-Z]+-\d+ \|/gm)];

describe('#978 OpenClaw check tables in docs/SECURITY_CHECKS.md', () => {
  it('parses the check tables and the auto-fix table', () => {
    expect(autoFixAt).toBeGreaterThan(-1);
    expect(checkRows.length).toBeGreaterThanOrEqual(47);
    expect(checkRows.length, 'a check row did not parse as id, severity, fixable, description').toBe(checkRowLines.length);
    expect(new Set(checkRows.map(r => r.id)).size).toBe(checkRows.length);
    expect(autoFixIds.length).toBeGreaterThan(0);
  });

  it.each(checkRows.map(r => [r.id, r]))('%s names the check the scanner reports', (id, row) => {
    const sites = scannerSites(id);
    expect(sites.length, `${id} is not reported by the scanner`).toBeGreaterThan(0);
    const names = sites.map(s => s.name);
    expect(
      names.some(name => opensWithName(row.description, name)),
      `${id} is reported as: ${names.join(' / ')}; the row reads: ${row.description}`,
    ).toBe(true);
  });

  it.each(checkRows.map(r => [r.id, r]))('%s carries the severity the scanner reports', (id, row) => {
    const expected = [...new Set(scannerSites(id).flatMap(s => s.severities))].sort();
    const documented = SEVERITIES.filter(s => new RegExp(`\\b${s}\\b`, 'i').test(row.severity)).sort();
    expect(documented).toEqual(expected);
  });

  it.each(checkRows.map(r => [r.id, r]))('%s is marked fixable only when the scanner can fix it', (id, row) => {
    expect(row.fixable).toBe(scannerSites(id).some(s => s.fixable));
  });

  it('the auto-fix table lists exactly the rows marked fixable', () => {
    expect([...autoFixIds].sort()).toEqual(checkRows.filter(r => r.fixable).map(r => r.id).sort());
  });
});
