/**
 * The exit-surface ratchet (#350): a BIJECTION between every bare
 * `process.exit(...)` call / bare `process.exitCode` assignment in `src/`
 * and the shrink-only registry in `exit-surface-baseline.ts`.
 *
 * A hard exit ends the process before Commander's postAction hook, so the
 * run emits NO telemetry event — the fleet metric counts it as if it never
 * ran, which is the #350 inversion (failures invisible, aggregate reads
 * healthy). A bare `process.exitCode` assignment can LOWER a floor a
 * stricter arm already raised (#512/#656). This test holds the surface.
 *
 * DIVISION OF LABOR (#285): this file carries the STRUCTURAL claim only —
 * "no exit syntax exists outside the funnel or the registry" — stated by
 * the AST (which distinguishes a comment from code and `=` from `===`;
 * substring grep does neither, and both failure modes were measured on this
 * very file's census: 88 grep hits vs 74 code sites, 25 vs 21). It never
 * carries the BEHAVIORAL claim ("the event fires with the right success
 * value") — that lives on `command-success.test.ts` and the spawn fixtures,
 * against the real `successFromExitCode`.
 *
 * KNOWN BLIND SPOT (documented, not silently held): an alias spelling
 * (`const p = process; p.exitCode = 1`) evades both selectors. None exists
 * today; if one ever appears in a PR, the selector gains that spelling — a
 * rule per spelling, added on evidence.
 */
import { describe, it, expect } from 'vitest';
import ts from 'typescript';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { UNSETTLED_EXIT_IDS, EXEMPTION_TAGS, FUNNEL_FUNCTIONS } from './exit-surface-baseline';

const SRC = path.join(__dirname, '..', '..', 'src');

interface Site {
  file: string;
  line: number;
  kind: 'exit' | 'assign';
  inAction: boolean;
  enclosingFn: string;
  annotation:
    | { form: 'unsettled'; id: string }
    | { form: 'no-event'; tag: string }
    | undefined;
  statement: string;
}

function* walkFiles(dir: string): Generator<string> {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) yield* walkFiles(p);
    else if (name.endsWith('.ts') && !name.endsWith('.d.ts')) yield p;
  }
}

function readAnnotation(lines: string[], lineIdx: number): Site['annotation'] {
  // The sweep's uniform style: on the statement's line, or the line above.
  for (const text of [lines[lineIdx] ?? '', lines[lineIdx - 1] ?? '']) {
    const unsettled = text.match(/exit-unsettled\(#350\/(S\d+)\)/);
    if (unsettled) return { form: 'unsettled', id: unsettled[1] };
    const noEvent = text.match(/exit-no-event\(([a-z-]+)\)/);
    if (noEvent) return { form: 'no-event', tag: noEvent[1] };
  }
  return undefined;
}

function collectSites(): Site[] {
  const sites: Site[] = [];
  for (const file of walkFiles(SRC)) {
    const text = fs.readFileSync(file, 'utf8');
    const lines = text.split('\n');
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node): void => {
      let kind: Site['kind'] | undefined;
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText(sf) === 'process' &&
        node.expression.name.text === 'exit'
      ) kind = 'exit';
      if (
        ts.isBinaryExpression(node) &&
        [
          ts.SyntaxKind.EqualsToken,
          ts.SyntaxKind.QuestionQuestionEqualsToken,
          ts.SyntaxKind.BarBarEqualsToken,
          ts.SyntaxKind.AmpersandAmpersandEqualsToken,
        ].includes(node.operatorToken.kind) &&
        ts.isPropertyAccessExpression(node.left) &&
        node.left.expression.getText(sf) === 'process' &&
        node.left.name.text === 'exitCode'
      ) kind = 'assign';
      if (kind) {
        let inAction = false;
        let enclosingFn = '';
        for (let a: ts.Node | undefined = node.parent; a; a = a.parent) {
          if (
            ts.isCallExpression(a) &&
            ts.isPropertyAccessExpression(a.expression) &&
            a.expression.name.text === 'action'
          ) inAction = true;
          if (!enclosingFn && (ts.isFunctionDeclaration(a) || ts.isFunctionExpression(a)) && a.name) enclosingFn = a.name.text;
        }
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        sites.push({
          file: path.relative(path.join(SRC, '..'), file),
          line: line + 1,
          kind,
          inAction,
          enclosingFn,
          annotation: readAnnotation(lines, line),
          statement: node.getText(sf).slice(0, 60).replace(/\s+/g, ' '),
        });
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return sites;
}

const sites = collectSites();

function owed(site: Site): string {
  return (
    `NEW UNSETTLED EXIT SITE: ${site.file}:${site.line} \`${site.statement}\`. ` +
    `A hard exit here ends the process before Commander's postAction hook, so this run emits NO telemetry event — ` +
    `the fleet metric counts it as if it never ran, which is the #350 inversion (failures invisible, aggregate reads healthy). ` +
    `A bare process.exitCode assignment can also LOWER a floor a stricter arm already raised (#512/#656). ` +
    `You owe one decision in this diff: (a) end through the settlement funnel — finishWithFindings(code) / raiseExitCode(code) / ` +
    `exitRecorded(code, reason) — so the event fires and the code can only rise; or (b) if this site is genuinely event-free, ` +
    `annotate // exit-no-event(<tag>) (tags: ${[...EXEMPTION_TAGS].join(', ')}) and add the claim-bearing row to ` +
    `__tests__/telemetry/exit-surface-baseline.ts; or (c) if the funnel is wrong for this case, reopen #350 — do not route ` +
    `around the gate. The unsettled baseline only shrinks. AST-checked, not grepped: see src/telemetry/command-success.ts on #285.`
  );
}

describe('the exit-surface ratchet (#350)', () => {
  it('the walker found the surface — a dead instrument never reads as clean', () => {
    // The registry is non-empty by construction; a walker that parses
    // nothing would report zero sites against it and MUST fail here.
    expect(sites.length).toBeGreaterThan(0);
    expect(UNSETTLED_EXIT_IDS.size).toBeGreaterThan(0);
  });

  it('every bare site is funnel-owned, registered unsettled, or carries a checkable exemption claim', () => {
    const problems: string[] = [];
    for (const site of sites) {
      if (FUNNEL_FUNCTIONS.has(site.enclosingFn)) continue;
      if (!site.annotation) {
        problems.push(owed(site));
        continue;
      }
      if (site.annotation.form === 'unsettled') {
        if (!UNSETTLED_EXIT_IDS.has(site.annotation.id)) {
          problems.push(
            `${site.file}:${site.line} carries exit-unsettled id ${site.annotation.id}, which is NOT in the baseline. ` +
              `The unsettled list only shrinks; a new dark exit site needs a CISO-lane ruling. ${owed(site)}`,
          );
        }
      } else {
        if (!EXEMPTION_TAGS.has(site.annotation.tag)) {
          problems.push(`${site.file}:${site.line} claims unknown exemption tag '${site.annotation.tag}'.`);
        }
        if (site.annotation.tag === 'pre-action' && site.inAction) {
          problems.push(
            `${site.file}:${site.line} claims exit-no-event(pre-action) but sits INSIDE a .action( callback — ` +
              `the claim's predicate (runs before telemetry is armed) no longer holds.`,
          );
        }
        if (site.annotation.tag === 'separate-entrypoint' && !site.file.startsWith(path.join('src', 'arp') + path.sep)) {
          problems.push(`${site.file}:${site.line} claims separate-entrypoint outside src/arp/.`);
        }
      }
    }
    expect(problems, problems.join('\n\n')).toEqual([]);
  });

  it('the bijection holds in reverse: every baseline id marks exactly one live site', () => {
    const seen = new Map<string, number>();
    for (const site of sites) {
      if (site.annotation?.form === 'unsettled') {
        seen.set(site.annotation.id, (seen.get(site.annotation.id) ?? 0) + 1);
      }
    }
    const orphaned = [...UNSETTLED_EXIT_IDS].filter((id) => !seen.has(id));
    const duplicated = [...seen.entries()].filter(([, n]) => n > 1).map(([id, n]) => `${id}×${n}`);
    expect(orphaned, `baseline ids with no live site (a migration must delete the id in the same diff): ${orphaned.join(', ')}`).toEqual([]);
    expect(duplicated, `ids used more than once (ids are unique names): ${duplicated.join(', ')}`).toEqual([]);
  });

  it('separate-entrypoint self-revokes: nothing outside src/arp imports the arp CLI', () => {
    const offenders: string[] = [];
    for (const file of walkFiles(SRC)) {
      if (file.includes(path.join('src', 'arp') + path.sep)) continue;
      const text = fs.readFileSync(file, 'utf8');
      if (/from ['"][^'"]*arp\/cli/.test(text)) offenders.push(path.relative(path.join(SRC, '..'), file));
    }
    expect(offenders, `src/arp/cli is imported by: ${offenders.join(', ')} — the separate-entrypoint exemption no longer holds`).toEqual([]);
  });

  it('the funnel functions exist and are the only unannotated writers', () => {
    const funnelSites = sites.filter((s) => FUNNEL_FUNCTIONS.has(s.enclosingFn));
    expect(funnelSites.length).toBeGreaterThanOrEqual(3);
    const unannotatedOutsideFunnel = sites.filter((s) => !FUNNEL_FUNCTIONS.has(s.enclosingFn) && !s.annotation);
    expect(unannotatedOutsideFunnel).toEqual([]);
  });
});
