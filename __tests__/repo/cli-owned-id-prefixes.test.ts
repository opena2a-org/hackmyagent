/**
 * hackmyagent never starts a check id with a prefix the opena2a CLI mints.
 *
 * `opena2a review` lists hackmyagent's findings and the CLI's own in one
 * `findings` array. When both tools use one id for two different checks,
 * anything keyed on the id (a suppression list, a dashboard, `explain`)
 * reads them as the same finding. The prefixes the CLI owns are listed once,
 * in src/cli-owned-id-prefixes.ts. This file holds hackmyagent to that list
 * in two places:
 *
 * 1. Every id `explain` answers for: the static table, the scan-soul findings
 *    and controls, and every TAXONOMY_MAP key.
 * 2. Every string literal and template-literal head under src/, parsed with
 *    the TypeScript compiler so that comments do not count. A literal equal to
 *    a prefix without its trailing dash counts too, because
 *    `${family}-${n}` with family 'DETECT' builds a reserved id at run time.
 *
 * Matching is case-sensitive. Check ids are upper-case, and the lower-case
 * command name 'detect' is not an id.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { CLI_OWNED_ID_PREFIXES, cliOwnedPrefixOf } from '../../src/cli-owned-id-prefixes';
import { getKnownExplainIds } from '../../src/explain-registry';

const SRC = path.join(__dirname, '..', '..', 'src');
const LIST_FILE = path.join(SRC, 'cli-owned-id-prefixes.ts');

function sourceFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(full, acc);
    else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) acc.push(full);
  }
  return acc;
}

/** A literal that starts a CLI-owned id, or is a CLI-owned family on its own. */
function isReservedLiteral(text: string): boolean {
  if (cliOwnedPrefixOf(text) !== undefined) return true;
  return CLI_OWNED_ID_PREFIXES.some((prefix) => text === prefix.slice(0, -1));
}

/** `line:text` for each string literal or template head in `source` that is reserved. */
function reservedLiterals(fileName: string, source: string): string[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const hits: string[] = [];
  const visit = (node: ts.Node): void => {
    if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node)) &&
      isReservedLiteral(node.text)
    ) {
      const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
      hits.push(`${line + 1}:${node.text}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return hits;
}

describe('the opena2a CLI owns its finding-id prefixes', () => {
  it('lists DETECT- and CONFIG-GUARD-, each upper-case and ending in a dash', () => {
    expect(CLI_OWNED_ID_PREFIXES).toEqual(expect.arrayContaining(['DETECT-', 'CONFIG-GUARD-']));
    for (const prefix of CLI_OWNED_ID_PREFIXES) {
      expect(prefix).toMatch(/^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-$/);
    }
  });

  it('matches an id that starts with a CLI-owned prefix and nothing else', () => {
    expect(cliOwnedPrefixOf('DETECT-CREDENTIALS-001')).toBe('DETECT-');
    expect(cliOwnedPrefixOf('CONFIG-GUARD-002')).toBe('CONFIG-GUARD-');
    expect(cliOwnedPrefixOf('CONFIG-001')).toBeUndefined();
    expect(cliOwnedPrefixOf('CONFIG-EXPOSED')).toBeUndefined();
    expect(cliOwnedPrefixOf('DETECTION-001')).toBeUndefined();
    expect(cliOwnedPrefixOf('detect')).toBeUndefined();
  });

  it('no id that explain answers for begins with a CLI-owned prefix', () => {
    const ids = [...getKnownExplainIds()];
    expect(ids.length).toBeGreaterThan(100);
    expect(ids.filter((id) => cliOwnedPrefixOf(id) !== undefined)).toEqual([]);
  });

  it('the source census flags a reserved id in every form a check can be written', () => {
    const planted = [
      "const a = { checkId: 'DETECT-001' };",
      'const b = { checkId: "CONFIG-GUARD-002" };',
      'const c = { checkId: `DETECT-${n}` };',
      "const family = 'DETECT';",
      '// DETECT-003 in a comment is not an id',
      "const d = { checkId: 'CONFIG-001', name: 'detect' };",
    ].join('\n');
    expect(reservedLiterals('planted.ts', planted)).toEqual([
      '1:DETECT-001',
      '2:CONFIG-GUARD-002',
      '3:DETECT-',
      '4:DETECT',
    ]);
  });

  it('no string literal under src/ starts a check id with a CLI-owned prefix', () => {
    const files = sourceFiles(SRC).filter((f) => f !== LIST_FILE);
    expect(files.length).toBeGreaterThan(100);
    const violations: string[] = [];
    for (const file of files) {
      const rel = path.relative(SRC, file).split(path.sep).join('/');
      for (const hit of reservedLiterals(file, readFileSync(file, 'utf8'))) {
        violations.push(`src/${rel}:${hit}`);
      }
    }
    expect(
      violations,
      'A hackmyagent check id must not begin with a prefix the opena2a CLI owns ' +
        '(src/cli-owned-id-prefixes.ts). Pick a hackmyagent family for the check.',
    ).toEqual([]);
  });
});
