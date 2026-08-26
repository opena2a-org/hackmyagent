/**
 * The exit-surface ratchet (#350): a BIJECTION between every bare
 * `process.exit(...)` call / bare `process.exitCode` assignment in `src/`
 * and the shrink-only registries in `exit-surface-baseline.ts`.
 *
 * A hard exit ends the process before Commander's postAction hook, so the
 * run emits NO telemetry event — the fleet metric counts it as if it never
 * ran, which is the #350 inversion (failures invisible, aggregate reads
 * healthy). A bare `process.exitCode` assignment can LOWER a floor a
 * stricter arm already raised (#512/#656). This test holds the surface.
 *
 * DIVISION OF LABOR (#285): this file carries the STRUCTURAL claim only —
 * "no exit syntax exists outside the funnel or the registries" — stated by
 * the AST (which distinguishes a comment from code and `=` from `===`;
 * substring grep does neither, and both failure modes were measured on this
 * very file's census: 88 grep hits vs 74 code sites, 25 vs 21). It never
 * carries the BEHAVIORAL claim ("the event fires with the right success
 * value") — that lives on `command-success.test.ts` and the spawn fixtures,
 * against the real `successFromExitCode`.
 *
 * ANNOTATIONS ARE COMMENTS, NOT TEXT: claims are read from the statement's
 * own trailing comment or an alone-on-its-line leading comment, via the
 * AST's comment ranges. A claim spelled inside a string literal, or sitting
 * on a neighbouring code line, attaches to nothing (an adversarial round
 * measured both of those forging the earlier text-scan reader).
 *
 * EVERY CLAIM CARRIES A REGISTERED ID — `exit-unsettled(#350/Snnn)` and
 * `exit-no-event(tag/Lnnn)` alike — so a new dark exit is always a baseline
 * edit reviewed as a gate change, never a one-line comment. Structural
 * checks ride on top where the tag's predicate is lexically visible.
 *
 * KNOWN BLIND SPOTS (documented, not silently held): an alias spelling
 * (`const p = process; p.exitCode = 1`) evades both selectors — none exists
 * today; and `pre-action`'s lexical check cannot see the call graph, which
 * is why its member list is closed. A rule per spelling, added on evidence.
 */
import { describe, it, expect } from 'vitest';
import ts from 'typescript';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  UNSETTLED_EXIT_IDS,
  NO_EVENT_EXIT_SITES,
  EXEMPTION_TAGS,
  FUNNEL_FUNCTIONS,
} from './exit-surface-baseline';

const SRC = path.join(__dirname, '..', '..', 'src');
const ARP_CLI_DIR = path.join('src', 'arp', 'cli') + path.sep;

interface Site {
  file: string;
  line: number;
  kind: 'exit' | 'assign';
  inAction: boolean;
  enclosingFn: string;
  annotation:
    | { form: 'unsettled'; id: string }
    | { form: 'no-event'; tag: string; id: string }
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

/** Climb from the matched expression to the statement that carries its comments. */
function enclosingStatement(node: ts.Node): ts.Node {
  let n: ts.Node = node;
  while (n.parent && !ts.isSourceFile(n.parent) && !ts.isBlock(n.parent) &&
         !ts.isCaseClause(n.parent) && !ts.isDefaultClause(n.parent) && !ts.isModuleBlock(n.parent)) {
    // Stop at the expression statement even when it hangs off an `if` with
    // no braces — its own end position is where the trailing comment lives.
    if (ts.isExpressionStatement(n)) break;
    n = n.parent;
  }
  return n;
}

function parseClaim(comment: string): Site['annotation'] {
  const unsettled = comment.match(/exit-unsettled\(#350\/(S\d+)\)/);
  if (unsettled) return { form: 'unsettled', id: unsettled[1] };
  const noEvent = comment.match(/exit-no-event\(([a-z-]+)\/(L\d+)\)/);
  if (noEvent) return { form: 'no-event', tag: noEvent[1], id: noEvent[2] };
  return undefined;
}

/**
 * Read the claim from the statement's COMMENTS: its trailing comment on the
 * same line, or a leading comment that is alone on its own line (a comment
 * that shares a line with preceding code is the PREVIOUS statement's
 * trailing comment, not this one's leading — the inheritance forgery).
 */
function readAnnotation(text: string, stmt: ts.Node): Site['annotation'] {
  for (const r of ts.getTrailingCommentRanges(text, stmt.end) ?? []) {
    const claim = parseClaim(text.slice(r.pos, r.end));
    if (claim) return claim;
  }
  for (const r of ts.getLeadingCommentRanges(text, stmt.getFullStart()) ?? []) {
    const lineStart = text.lastIndexOf('\n', r.pos) + 1;
    if (text.slice(lineStart, r.pos).trim() !== '') continue; // trailing of the previous statement
    const claim = parseClaim(text.slice(r.pos, r.end));
    if (claim) return claim;
  }
  return undefined;
}

function collectSites(): Site[] {
  const sites: Site[] = [];
  for (const file of walkFiles(SRC)) {
    const text = fs.readFileSync(file, 'utf8');
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
          annotation: readAnnotation(text, enclosingStatement(node)),
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

/** The funnel's own writes: named funnel function, in the file that defines the funnel. */
function funnelOwned(site: Site): boolean {
  return FUNNEL_FUNCTIONS.has(site.enclosingFn) && site.file === path.join('src', 'cli.ts');
}

function owed(site: Site): string {
  return (
    `NEW UNSETTLED EXIT SITE: ${site.file}:${site.line} \`${site.statement}\`. ` +
    `A hard exit here ends the process before Commander's postAction hook, so this run emits NO telemetry event — ` +
    `the fleet metric counts it as if it never ran, which is the #350 inversion (failures invisible, aggregate reads healthy). ` +
    `A bare process.exitCode assignment can also LOWER a floor a stricter arm already raised (#512/#656). ` +
    `You owe one decision in this diff: (a) end through the settlement funnel — finishWithFindings(code) / raiseExitCode(code) / ` +
    `exitRecorded(code, reason) — so the event fires and the code can only rise; or (b) if this site is genuinely event-free, ` +
    `annotate // exit-no-event(<tag>/L<id>) (tags: ${[...EXEMPTION_TAGS].join(', ')}) AND register the id with its tag in ` +
    `__tests__/telemetry/exit-surface-baseline.ts — a claim-bearing baseline edit, reviewed as a gate change; or (c) if the ` +
    `funnel is wrong for this case, reopen #350 — do not route around the gate. Both registries only shrink. ` +
    `AST-checked, not grepped: see src/telemetry/command-success.ts on #285.`
  );
}

describe('the exit-surface ratchet (#350)', () => {
  it('the walker found the surface — a dead instrument never reads as clean', () => {
    // The registries are non-empty by construction; a walker that parses
    // nothing would report zero sites against them and MUST fail here.
    expect(sites.length).toBeGreaterThan(0);
    expect(UNSETTLED_EXIT_IDS.size).toBeGreaterThan(0);
    expect(NO_EVENT_EXIT_SITES.size).toBeGreaterThan(0);
  });

  it('every bare site is funnel-owned, registered unsettled, or carries a REGISTERED exemption claim', () => {
    const problems: string[] = [];
    for (const site of sites) {
      if (funnelOwned(site)) continue;
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
        const registeredTag = NO_EVENT_EXIT_SITES.get(site.annotation.id);
        if (registeredTag === undefined) {
          problems.push(
            `${site.file}:${site.line} claims exit-no-event id ${site.annotation.id}, which is NOT registered. ` +
              `An exemption is a baseline edit, never a one-line comment. ${owed(site)}`,
          );
          continue;
        }
        if (registeredTag !== site.annotation.tag) {
          problems.push(
            `${site.file}:${site.line} claims tag '${site.annotation.tag}' on id ${site.annotation.id}, ` +
              `which is registered as '${registeredTag}' — the id licenses exactly one claim.`,
          );
        }
        if (!EXEMPTION_TAGS.has(site.annotation.tag)) {
          problems.push(`${site.file}:${site.line} claims unknown exemption tag '${site.annotation.tag}'.`);
        }
        if (site.annotation.tag === 'pre-action' && site.inAction) {
          problems.push(
            `${site.file}:${site.line} claims exit-no-event(pre-action) but sits INSIDE a .action( callback — ` +
              `the claim's predicate (runs before telemetry is armed) no longer holds.`,
          );
        }
        if (site.annotation.tag === 'separate-entrypoint' && !site.file.startsWith(ARP_CLI_DIR)) {
          problems.push(
            `${site.file}:${site.line} claims separate-entrypoint outside src/arp/cli/ — only the standalone ` +
              `binary's own tree is licensed (src/arp/index.ts IS imported into the telemetry-bearing process).`,
          );
        }
      }
    }
    expect(problems, problems.join('\n\n')).toEqual([]);
  });

  it('the bijection holds in reverse: every registered id marks exactly one live site', () => {
    const seenS = new Map<string, number>();
    const seenL = new Map<string, number>();
    for (const site of sites) {
      if (site.annotation?.form === 'unsettled') seenS.set(site.annotation.id, (seenS.get(site.annotation.id) ?? 0) + 1);
      if (site.annotation?.form === 'no-event') seenL.set(site.annotation.id, (seenL.get(site.annotation.id) ?? 0) + 1);
    }
    const orphaned = [
      ...[...UNSETTLED_EXIT_IDS].filter((id) => !seenS.has(id)),
      ...[...NO_EVENT_EXIT_SITES.keys()].filter((id) => !seenL.has(id)),
    ];
    const duplicated = [
      ...[...seenS.entries()].filter(([, n]) => n > 1),
      ...[...seenL.entries()].filter(([, n]) => n > 1),
    ].map(([id, n]) => `${id}×${n}`);
    expect(orphaned, `registered ids with no live site (a migration must delete the id in the same diff): ${orphaned.join(', ')}`).toEqual([]);
    expect(duplicated, `ids used more than once (ids are unique names): ${duplicated.join(', ')}`).toEqual([]);
  });

  it('separate-entrypoint self-revokes: nothing outside src/arp/cli imports the arp CLI, in any spelling', () => {
    // Four import spellings, because the repo uses all of them elsewhere:
    // static `from`, `require(...)`, dynamic `import(...)`, and the bare
    // side-effect `import '...'`. An adversarial round measured the earlier
    // single-regex version blind to three of the four.
    const spellings = [
      /from\s+['"][^'"]*arp\/cli/,
      /require\(\s*['"][^'"]*arp\/cli/,
      /import\(\s*['"][^'"]*arp\/cli/,
      /^\s*import\s+['"][^'"]*arp\/cli/m,
    ];
    const offenders: string[] = [];
    for (const file of walkFiles(SRC)) {
      const rel = path.relative(path.join(SRC, '..'), file);
      if (rel.startsWith(ARP_CLI_DIR)) continue;
      const text = fs.readFileSync(file, 'utf8');
      if (spellings.some((re) => re.test(text))) offenders.push(rel);
    }
    expect(offenders, `src/arp/cli is imported by: ${offenders.join(', ')} — the separate-entrypoint exemption no longer holds`).toEqual([]);
  });

  it('the funnel is exactly three writes in src/cli.ts, and nothing else is unannotated', () => {
    // A function elsewhere merely NAMED after a funnel member is not the
    // funnel (measured forgery: a decoy `raiseExitCode` in a new file).
    // Growing the funnel is a deliberate edit that fails this pin first.
    const funnelSites = sites.filter((s) => FUNNEL_FUNCTIONS.has(s.enclosingFn));
    expect(funnelSites.filter((s) => s.file !== path.join('src', 'cli.ts'))).toEqual([]);
    expect(funnelSites).toHaveLength(3);
    const unannotatedOutsideFunnel = sites.filter((s) => !funnelOwned(s) && !s.annotation);
    expect(unannotatedOutsideFunnel).toEqual([]);
  });
});
