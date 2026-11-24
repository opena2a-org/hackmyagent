/**
 * #426 — a check that fails on a positive match names the file it matched.
 *
 * `scan()` keeps a failed finding in the report only when it carries a `file`,
 * and `isReportableFinding` applies the same rule on every CLI refilter. A
 * check that matched something and recorded no path is therefore scored and
 * displayed as though it never fired.
 *
 * A failure with no file is legitimate only for ADVICE: a check that fails
 * because something is ABSENT ("no rate limiting library detected"), so no
 * file holds the problem. Any other pathless failure is a lost detection.
 *
 * Two cells hold the rule, because neither is enough on its own:
 *
 *  - SOURCE: every finding literal in scanner.ts that has no `file` property
 *    and can fail must name a check on one of the two lists below. This sees
 *    checks that no fixture triggers.
 *  - RUNTIME: every committed fixture is scanned, and every failed record on
 *    `allFindings` (the array the reportable filter rebuilds from) with no
 *    `file` must name a listed check. This sees checks built outside a
 *    literal, and a `file` that is present in the source but undefined when
 *    the check fails.
 *
 * A new check that fails without evidence fails this file. The fix is to
 * record the matched path in `file`. ADVICE is only for a check that fails on
 * an absence, and the advice cell refuses a site whose `passed` reads as a
 * match.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import ts from 'typescript';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

const SCANNER = path.resolve(__dirname, '../../src/hardening/scanner.ts');
const FIXTURES = path.resolve(__dirname, '../../test-fixtures');

/**
 * Checks that fail on an ABSENCE, so a failure has no file to name. Each one
 * passes on "has X" (a library, a config key, the pattern that would be the
 * mitigation) and fails when X is missing. IO-001, IO-002 and NET-005 fail
 * only when a capability is present (an upload library, a database library,
 * websockets) and its mitigation is missing: still an absence.
 */
const ADVICE: ReadonlySet<string> = new Set([
  'API-001', 'API-002', 'API-004',
  'AUDIT-001', 'AUDIT-002', 'AUDIT-003', 'AUDIT-004',
  'AUTH-001', 'AUTH-002', 'AUTH-003', 'AUTH-004',
  'CLAUDE-004', 'CLAUDE-007',
  'DEP-001',
  'ENCRYPT-001', 'ENCRYPT-002', 'ENCRYPT-004',
  'ENV-004',
  'INJ-001', 'INJ-002', 'INJ-003', 'INJ-004',
  'IO-001', 'IO-002', 'IO-003',
  'LOG-001', 'LOG-004',
  'NET-003', 'NET-005',
  'PROC-002', 'PROC-003', 'PROC-004',
  'PROMPT-001', 'PROMPT-002', 'PROMPT-003', 'PROMPT-004',
  'RATE-001', 'RATE-002', 'RATE-003', 'RATE-004',
  'SANDBOX-001', 'SANDBOX-002', 'SANDBOX-003', 'SANDBOX-004',
  'SEC-001', 'SEC-002', 'SEC-003',
  'SESSION-001', 'SESSION-002', 'SESSION-003', 'SESSION-004',
  'TOOL-004',
]);

/**
 * Checks that DO fail on a positive match and still record no file: the
 * members of the class #426 removes that are left on main. They are not
 * advice. This list only shrinks. When a check records the path it matched,
 * delete its entry (the stale-entry cell below fails until you do), and never
 * add one: a new check records its evidence instead.
 */
const KNOWN_UNEVIDENCED: ReadonlySet<string> = new Set([
  'API-003',
  'CLAUDE-005', 'CLAUDE-006',
  'CRED-003', 'CRED-004',
  'CURSOR-001',
  'DEP-002', 'DEP-003',
  'ENCRYPT-003',
  'ENV-001', 'ENV-002', 'ENV-003',
  'IO-004',
  'LOG-003',
  'NET-004',
  'PERM-002', 'PERM-003',
  'SEC-004',
  'VSCODE-001', 'VSCODE-002',
]);

function allowed(checkId: string): boolean {
  return ADVICE.has(checkId) || KNOWN_UNEVIDENCED.has(checkId);
}

interface PathlessSite {
  checkId: string;
  line: number;
  /** Source text of the `passed` value. */
  passed: string;
  /** True when `passed` reads as "nothing matched": `!hit`, `false`, `xs.length === 0`. */
  matchShaped: boolean;
}

function propName(p: ts.ObjectLiteralElementLike): string | undefined {
  if (!p.name) return undefined;
  if (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) return p.name.text;
  return undefined;
}

function isMatchShaped(init: ts.Expression): boolean {
  let e = init;
  while (ts.isParenthesizedExpression(e)) e = e.expression;
  if (e.kind === ts.SyntaxKind.FalseKeyword) return true;
  if (ts.isPrefixUnaryExpression(e) && e.operator === ts.SyntaxKind.ExclamationToken) return true;
  if (
    ts.isBinaryExpression(e)
    && (e.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
      || e.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken)
    && /\.(length|size)$/.test(e.left.getText())
    && e.right.getText() === '0'
  ) return true;
  return false;
}

/**
 * Every object literal with a string-literal `checkId`, a `passed` that is not
 * the literal `true`, and no `file` property. A spread is not trusted to
 * supply `file`: the literal must state it.
 */
function pathlessSites(source: string): PathlessSite[] {
  const sf = ts.createSourceFile('scanner.ts', source, ts.ScriptTarget.Latest, true);
  const out: PathlessSite[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      const props = new Map<string, ts.ObjectLiteralElementLike>();
      for (const p of node.properties) {
        const name = propName(p);
        if (name) props.set(name, p);
      }
      const checkId = props.get('checkId');
      const passed = props.get('passed');
      if (
        checkId && ts.isPropertyAssignment(checkId) && ts.isStringLiteralLike(checkId.initializer)
        && passed && !props.has('file')
      ) {
        const init: ts.Expression = ts.isPropertyAssignment(passed)
          ? passed.initializer
          : (passed.name as ts.Identifier);
        if (init.kind !== ts.SyntaxKind.TrueKeyword) {
          out.push({
            checkId: checkId.initializer.text,
            line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1,
            passed: init.getText().replace(/\s+/g, ' '),
            matchShaped: isMatchShaped(init),
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

interface RecordLike {
  checkId: string;
  passed?: boolean;
  fixed?: boolean;
  file?: string;
  message?: string;
  notApplicable?: unknown;
}

/** Failed records that name no file and no listed check. */
function unevidenced(records: readonly RecordLike[]): RecordLike[] {
  return records.filter((f) =>
    !f.notApplicable && f.passed === false && !f.fixed && !f.file && !allowed(f.checkId));
}

describe('the guard itself catches an unevidenced positive match', () => {
  it('source: a pathless literal that can fail is reported, an evidenced one is not', () => {
    const src = `
      findings.push({ checkId: 'ZZZ-901', passed: !hit, message: 'matched' });
      findings.push({ checkId: 'ZZZ-902', passed: !hit, file: hitFile, message: 'matched' });
      findings.push({ checkId: 'ZZZ-903', passed: true, message: 'ok' });
      findings.push({ checkId: 'ZZZ-904', passed: hits.length === 0, message: 'matched' });
      findings.push({ checkId: 'ZZZ-905', passed: hasGuard, message: 'no guard' });
    `;
    const sites = pathlessSites(src);
    expect(sites.map((s) => s.checkId)).toEqual(['ZZZ-901', 'ZZZ-904', 'ZZZ-905']);
    expect(sites.map((s) => s.matchShaped)).toEqual([true, true, false]);
    expect(sites.filter((s) => !allowed(s.checkId))).toHaveLength(3);
  });

  it('runtime: a failed record with no file is reported unless its check is listed', () => {
    const records: RecordLike[] = [
      { checkId: 'ZZZ-901', passed: false },
      { checkId: 'ZZZ-902', passed: false, file: 'src/a.ts' },
      { checkId: 'ZZZ-903', passed: true },
      { checkId: 'ZZZ-904', notApplicable: { subject: 'x', reason: 'y' } },
      { checkId: 'ZZZ-905', passed: false, fixed: true },
      { checkId: 'AUTH-002', passed: false },
      { checkId: 'LOG-003', passed: false },
    ];
    expect(unevidenced(records).map((f) => f.checkId)).toEqual(['ZZZ-901']);
  });
});

describe('scanner.ts: a check that can fail without a file is advice or already known', () => {
  const sites = pathlessSites(fs.readFileSync(SCANNER, 'utf-8'));

  it('finds the pathless sites it is meant to read', () => {
    // A parse that silently found nothing would pass every row below.
    expect(sites.length).toBeGreaterThanOrEqual(ADVICE.size);
    expect(sites.some((s) => s.checkId === 'AUTH-002')).toBe(true);
  });

  it('no unlisted check fails without recording a file', () => {
    const offenders = sites
      .filter((s) => !allowed(s.checkId))
      .map((s) => `scanner.ts:${s.line} ${s.checkId} passed: ${s.passed}`);
    expect(
      offenders,
      'these findings can fail with no `file`, so scan() drops them from every report; record the matched path in `file` (or, for a check that fails on an absence, add it to ADVICE)',
    ).toEqual([]);
  });

  it('no check on the advice list fails on a match', () => {
    const laundered = sites
      .filter((s) => ADVICE.has(s.checkId) && s.matchShaped)
      .map((s) => `scanner.ts:${s.line} ${s.checkId} passed: ${s.passed}`);
    expect(
      laundered,
      'a `passed` that is a negation, `false` or an emptiness test fails when something MATCHED; that is evidence, so record it in `file` instead of listing the check as advice',
    ).toEqual([]);
  });

  it('every known unevidenced check still has a pathless site (the list only shrinks)', () => {
    const present = new Set(sites.map((s) => s.checkId));
    const stale = [...KNOWN_UNEVIDENCED].filter((id) => !present.has(id));
    expect(
      stale,
      'these checks now record a file; delete them from KNOWN_UNEVIDENCED so the class cannot regrow under their ids',
    ).toEqual([]);
  });

  it('the two lists do not overlap', () => {
    expect([...ADVICE].filter((id) => KNOWN_UNEVIDENCED.has(id))).toEqual([]);
  });
});

describe('committed fixtures: no failed record without a file outside the lists', () => {
  const fixtures = fs.readdirSync(FIXTURES)
    .filter((name) => fs.statSync(path.join(FIXTURES, name)).isDirectory())
    .sort();

  it('has fixtures to scan', () => {
    expect(fixtures).toContain('insecure-api');
    expect(fixtures).toContain('insecure-mcp');
  });

  for (const name of fixtures) {
    it(name, async () => {
      // Scan a copy outside the repository, so the worktree's git state and
      // `.hmaignore` are not part of the fixture.
      const dir = tempDir('hma-unevidenced-');
      fs.cpSync(path.join(FIXTURES, name), dir, { recursive: true });
      const result = await new HardeningScanner().scan({ targetDir: dir });
      const records: readonly RecordLike[] = result.allFindings ?? result.findings;
      const offenders = unevidenced(records).map((f) => `${f.checkId}: ${f.message ?? ''}`);
      expect(
        offenders,
        `${name}: failed findings with no file are dropped from every report; record the matched path in \`file\``,
      ).toEqual([]);
    }, 120_000);
  }
});
