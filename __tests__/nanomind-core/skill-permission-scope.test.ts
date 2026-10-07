/**
 * Issue #471 — a skill's declared permissions reach AST-SCOPE-001.
 *
 * `SemanticCompiler.extractDeclaredCapabilities` read capabilities from MCP
 * configs and frontmatter but not from a skill's `## Permissions` list, so
 * `AST-SCOPE-001` could never fire from a skill. The first attempt at reading
 * the list was withdrawn after review measured five failure modes on ordinary
 * skills; each has a block below, run through the REAL compiler into the REAL
 * analyzer, and each block asserts something the unfixed compiler cannot
 * produce (it reads no grant at all), so none passes against it.
 *
 * Grading, as ruled for this issue: a grant is a capability signal. An
 * unbounded grant reports MEDIUM at its own line with a fix naming a narrower
 * value, reaches HIGH only when the purpose-mismatch analysis finds it
 * contradicts the skill's stated purpose, and never reaches CRITICAL from a
 * declaration alone.
 *
 * The published-skill block at the end runs real SKILL.md files, copied byte
 * for byte with their source URL, commit and license in
 * `__tests__/fixtures/skill-permissions/sources.json`.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzeScope } from '../../src/nanomind-core/analyzers/scope-analyzer';
import { analyzePrompt } from '../../src/nanomind-core/analyzers/prompt-analyzer';
import { analyzeGovernance } from '../../src/nanomind-core/analyzers/governance-analyzer';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { generateVerifyCommand } from '../../src/ui/verify-command';
import { MAX_SKILL_PERMISSION_GRANTS } from '../../src/nanomind-core/compiler/skill-permissions';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';
import type { SecurityAST } from '../../src/nanomind-core/types';
import { tempDir } from '../helpers/temp-dir';

const compiler = new SemanticCompiler({ useNanoMind: false }); // heuristic mode
const pass = () => true;

async function compileSkill(md: string): Promise<{ ast: SecurityAST; scope: ASTFinding[] }> {
  const { ast } = await compiler.compile(md, 'SKILL.md');
  return { ast, scope: analyzeScope(ast, pass, undefined, md) };
}

/** The capabilities a Permissions list contributed, as domain/value/line. */
function grantsOf(ast: SecurityAST): Array<[string, string, number | undefined]> {
  return ast.declaredCapabilities
    .filter(c => c.source === 'skill-permissions')
    .map(c => [c.name, c.scope, c.line]);
}

/** Governance findings as checkId|severity|line, for comparing two compiles. */
async function governanceRows(md: string): Promise<string[]> {
  const { ast } = await compiler.compile(md, 'SKILL.md');
  return analyzeGovernance(ast, pass, undefined, undefined, md)
    .map(f => `${f.checkId}|${f.severity}|${f.line ?? '-'}`)
    .sort();
}

/** `md` with the given 1-based lines emptied, so every other line keeps its number. */
function withoutLines(md: string, lines: number[]): string {
  const out = md.split('\n');
  for (const n of lines) out[n - 1] = '';
  return out.join('\n');
}

function unboundedGrants(findings: ASTFinding[]): ASTFinding[] {
  return findings.filter(f => f.checkId === 'AST-SCOPE-001' && f.name === 'Unbounded Skill Permission');
}

describe('#471 the issue example reaches AST-SCOPE-001', () => {
  const md = ['# Ops helper', '', '## Permissions', '- filesystem:/', '- shell:*', '- network:*', ''].join('\n');

  it('one MEDIUM finding per grant, at the grant line, with a Verify command', async () => {
    const { ast, scope } = await compileSkill(md);
    expect(grantsOf(ast)).toEqual([
      ['filesystem', '/', 4],
      ['shell', '*', 5],
      ['network', '*', 6],
    ]);
    const found = unboundedGrants(scope);
    expect(found.map(f => [f.severity, f.line])).toEqual([
      ['medium', 4],
      ['medium', 5],
      ['medium', 6],
    ]);
    expect(found.map(f => generateVerifyCommand({ file: f.file, line: f.line }))).toEqual([
      "sed -n '4p' 'SKILL.md'",
      "sed -n '5p' 'SKILL.md'",
      "sed -n '6p' 'SKILL.md'",
    ]);
  });
});

describe('#471 failure mode 1: an ordinary glob is not a finding', () => {
  // The 5-line log-rotation skill the first attempt scored 63/100, "Not safe
  // to ship", exit 1, off a CRITICAL "equivalent of running as root".
  const md = [
    '---',
    'name: log-rotate',
    'description: Rotate and compress application log files under /var/log',
    '---',
    '# Log rotate',
    '',
    '## Permissions',
    '- logs: /var/log/*.*',
    '- filesystem: /var/log/*.*',
    '',
  ].join('\n');

  it('`- logs: /var/log/*.*` raises no CRITICAL; the filesystem glob beside it is read and raises no AST-SCOPE-001', async () => {
    const { ast, scope } = await compileSkill(md);
    // Read as a grant (the unfixed compiler reads none), and `logs` is not a domain.
    expect(grantsOf(ast)).toEqual([['filesystem', '/var/log/*.*', 9]]);
    expect(scope.filter(f => f.checkId === 'AST-SCOPE-001')).toEqual([]);
    expect(scope.filter(f => f.severity === 'critical')).toEqual([]);
  });

  it('the whole AST scan raises nothing CRITICAL, and nothing at HIGH or above on either grant line', async () => {
    const dir = tempDir('hma-471-');
    await writeFile(path.join(dir, 'SKILL.md'), md);
    const { astFindings } = await runNanoMindScan(dir, []);
    expect(astFindings.filter(f => !f.passed && f.severity === 'critical')).toEqual([]);
    expect(
      astFindings.filter(f => !f.passed && (f.line === 8 || f.line === 9) && (f.severity === 'high' || f.severity === 'critical')),
    ).toEqual([]);
  });
});

describe('#471 failure mode 2: one-token spellings are read', () => {
  it.each([
    ['## Permissions', '- shell: * # needed for build'],
    ['## Permissions', '- network: * (egress)'],
    ['## Permissions Required', '- shell: *'],
    ['## Required Permissions', '- shell: *'],
    ['## Permissions:', '- shell: *'],
    ['   ## Permissions', '- shell: *'],
    ['## Permissions', '+ shell: *'],
    ['## Permissions', '1. shell: *'],
    ['## Permissions', '| shell: * | build |'],
    ['## Permissions', '| shell | * | build |'],
  ])('%j / %j', async (heading, item) => {
    const md = `# Tool\n\n${heading}\n${item}\n`;
    const found = unboundedGrants((await compileSkill(md)).scope);
    expect(found.map(f => [f.severity, f.line])).toEqual([['medium', 4]]);
  });
});

describe('#471 failure mode 3: nothing but a grant is captured', () => {
  it('Note, Contact and See bullets are not capabilities; the grant beside them is', async () => {
    const md = [
      '# Tool',
      '',
      '## Permissions',
      '- Note: none',
      '- Contact: security@example.com',
      '- See: docs/PERMISSIONS.md',
      '- shell: make test',
      '',
    ].join('\n');
    const { ast } = await compileSkill(md);
    expect(grantsOf(ast)).toEqual([['shell', 'make test', 7]]);
  });

  it('a fenced example Permissions section yields no capability; the real one does', async () => {
    const md = [
      '# Writing a skill',
      '',
      'Declare grants like this:',
      '',
      '```markdown',
      '## Permissions',
      '- shell: *',
      '- filesystem: /',
      '```',
      '',
      '## Permissions',
      '- filesystem: ./skills',
      '',
    ].join('\n');
    const { ast, scope } = await compileSkill(md);
    expect(grantsOf(ast)).toEqual([['filesystem', './skills', 12]]);
    expect(unboundedGrants(scope)).toEqual([]);
  });

  it('`##Overview` ends the section, and `- token: sk-live-…` after it is neither a capability nor echoed', async () => {
    const token = ['sk', '-live-EXAMPLE0000000000000000000000'].join('');
    const md = [
      '# Tool',
      '',
      '## Permissions',
      '- network: *',
      '##Overview',
      `- token: ${token}`,
      '',
    ].join('\n');
    const { ast, scope } = await compileSkill(md);
    expect(grantsOf(ast)).toEqual([['network', '*', 4]]);
    expect(JSON.stringify(ast.declaredCapabilities)).not.toContain('sk-live');
    expect(JSON.stringify(scope)).not.toContain('sk-live');
  });

  it('a `token:` bullet inside the section is not a capability either', async () => {
    const token = ['sk', '-live-EXAMPLE0000000000000000000000'].join('');
    const md = `# Tool\n\n## Permissions\n- token: ${token}\n- shell: make\n`;
    const { ast, scope } = await compileSkill(md);
    expect(grantsOf(ast)).toEqual([['shell', 'make', 5]]);
    expect(JSON.stringify(ast.declaredCapabilities)).not.toContain('sk-live');
    expect(JSON.stringify(scope)).not.toContain('sk-live');
  });
});

describe('#471 failure mode 4: the conventional spelling has its line', () => {
  it('`- shell: *` resolves to its line and a Verify command', async () => {
    const md = '# Tool\n\n## Permissions\n- shell: *\n';
    const [f] = unboundedGrants((await compileSkill(md)).scope);
    expect(f.line).toBe(4);
    expect(generateVerifyCommand({ file: f.file, line: f.line })).toBe("sed -n '4p' 'SKILL.md'");
  });

  it('an identical example line above the list does not take the citation', async () => {
    const md = ['```', '## Permissions', '- shell: *', '```', '', '## Permissions', '- shell: *', ''].join('\n');
    const found = unboundedGrants((await compileSkill(md)).scope);
    expect(found.map(f => f.line)).toEqual([7]);
  });
});

describe('#471 failure mode 5: an attacker-sized list is bounded and linear', () => {
  it('40,000 bullets: the first grants are read, the rest disclosed, in linear time', async () => {
    const lines = ['# Big', '', '## Permissions'];
    for (let i = 0; i < 40_000; i++) lines.push('- shell: *');
    const md = lines.join('\n') + '\n';

    const t0 = performance.now();
    const { ast } = await compiler.compile(md, 'SKILL.md');
    const t1 = performance.now();
    const scope = analyzeScope(ast, pass, undefined, md);
    const t2 = performance.now();
    console.log(
      `#471 40,000 bullets (${md.length} bytes): compile ${(t1 - t0).toFixed(0)}ms, ` +
        `analyzeScope ${(t2 - t1).toFixed(0)}ms`,
    );

    expect(grantsOf(ast)).toHaveLength(MAX_SKILL_PERMISSION_GRANTS);
    expect(unboundedGrants(scope)).toHaveLength(MAX_SKILL_PERMISSION_GRANTS);
    const unread = scope.filter(f => f.name === 'Skill Permission List Not Fully Read');
    expect(unread).toHaveLength(1);
    expect(unread[0].severity).toBe('low');
    expect(unread[0].line).toBe(3 + MAX_SKILL_PERMISSION_GRANTS + 1);
    expect(unread[0].message).toContain(String(40_000 - MAX_SKILL_PERMISSION_GRANTS));
    // The first attempt measured 27,528ms for analyzeScope alone at this size.
    expect(t2 - t1).toBeLessThan(2_000);
  });
});

describe('#471 grading', () => {
  it('`shell: *` in a skill whose purpose is shell work is MEDIUM, with a narrower value in the fix', async () => {
    const md = [
      '---',
      'name: builder',
      'description: Runs build commands and shell scripts for the project',
      '---',
      '# Builder',
      '',
      '## Permissions',
      '- shell: *',
      '',
    ].join('\n');
    const [f, ...rest] = unboundedGrants((await compileSkill(md)).scope);
    expect(rest).toEqual([]);
    expect(f.severity).toBe('medium');
    expect(f.line).toBe(8);
    expect(f.fix).toContain('"shell: git status"');
  });

  it('`shell: *` in a skill that formats dates is HIGH, never CRITICAL', async () => {
    const md = [
      '---',
      'name: date-format',
      'description: Formats calendar dates into ISO 8601 strings',
      '---',
      '# Date format',
      '',
      '## Permissions',
      '- shell: *',
      '',
    ].join('\n');
    const { ast, scope } = await compileSkill(md);
    const [f, ...rest] = unboundedGrants(scope);
    expect(rest).toEqual([]);
    expect(f.severity).toBe('high');
    expect(f.line).toBe(8);
    expect(scope.filter(x => x.severity === 'critical')).toEqual([]);
    // The grant is graded once, here: its capability stays below the
    // purpose-mismatch and governance analyzers' high/critical selectors.
    expect(ast.declaredCapabilities.find(c => c.source === 'skill-permissions')?.riskLevel).toBe('medium');
    expect(scope.filter(x => x.checkId === 'AST-SCOPE-003' && x.message.includes('"shell"'))).toEqual([]);
  });

  it('a Permissions list is a manifest, not capability creep beyond one', async () => {
    const md = [
      '---',
      'name: reporter',
      'description: Builds weekly status reports from the repository',
      'capabilities:',
      '  - report.write',
      '---',
      '# Reporter',
      '',
      '## Permissions',
      '- filesystem: ./reports',
      '- shell: git log',
      '- network: api.github.com',
      '',
    ].join('\n');
    const { ast } = await compiler.compile(md, 'SKILL.md');
    expect(grantsOf(ast)).toHaveLength(3);
    expect(analyzePrompt(ast, pass, undefined, md).filter(f => f.checkId === 'AST-PROMPT-002')).toEqual([]);
  });

  it('a Permissions list adds no governance finding: grants are graded once, by AST-SCOPE-001', async () => {
    const md = ['# Tool', '', '## Permissions', '- shell: *', '- network: api.example.com', ''].join('\n');
    expect(grantsOf((await compiler.compile(md, 'SKILL.md')).ast)).toHaveLength(2);
    expect(await governanceRows(md)).toEqual(await governanceRows(withoutLines(md, [4, 5])));
  });
});

describe('#471 published skills', () => {
  const dir = path.join(__dirname, '..', 'fixtures', 'skill-permissions');
  const sources = JSON.parse(fs.readFileSync(path.join(dir, 'sources.json'), 'utf8')) as {
    fixtures: Array<{ fixture: string; url: string; commit: string; license: string; sha256: string }>;
  };

  // Read from each file by hand at its pinned commit.
  const EXPECTED: Record<string, Array<[string, string, number]>> = {
    // Bold keys, multi-word values, parenthetical comments.
    'clawforge-openclaw-skill/SKILL.md': [
      ['filesystem', 'For memory_backup, strategy_backtest', 73],
      ['network', 'Optional for strategy_backtest', 74],
      ['shell', 'Run metaskill CLI from OpenClaw', 75],
    ],
    // A table of upper-case keys in inline code; READ, WRITE and NOTIFY are
    // not domains, `EXEC: cp, mkdir` is a multi-word shell grant.
    'claw-mentor-mentee/SKILL.md': [
      ['network', 'app.clawmentor.ai', 90],
      ['shell', 'cp, mkdir', 92],
    ],
    // A level-3 heading over a table; `exec: false` and `filesystem: none`
    // decline the capability and are not grants.
    'hyperstack/SKILL.md': [
      ['network', 'api.hyperstack.dev', 73],
      ['network', 'HYPERSTACK_BASE_URL', 74],
      ['env', 'HYPERSTACK_API_KEY', 77],
      ['env', 'HYPERSTACK_WORKSPACE', 78],
      ['env', 'HYPERSTACK_AGENT_SLUG', 79],
    ],
    // `## Permissions` whose globs (`Read(src/**)`, `Write(**/*.md)`) sit in
    // fenced JSON examples: nothing in it is a grant.
    'letta-code-self-configuration/SKILL.md': [],
  };

  it('every fixture is pinned: source URL at a commit, a license, and its exact bytes', () => {
    expect(sources.fixtures.map(f => f.fixture).sort()).toEqual(Object.keys(EXPECTED).sort());
    for (const f of sources.fixtures) {
      expect(f.url).toMatch(new RegExp(`^https://github\\.com/[^/]+/[^/]+/blob/${f.commit}/`));
      expect(f.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(f.license).toMatch(/^(MIT|Apache-2\.0)$/);
      const bytes = fs.readFileSync(path.join(dir, f.fixture));
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(f.sha256);
    }
  });

  it.each(Object.keys(EXPECTED))('%s: its grants are read with their lines, and none is a finding', async fixture => {
    const md = fs.readFileSync(path.join(dir, fixture), 'utf8');
    const { ast, scope } = await compileSkill(md);
    expect(grantsOf(ast)).toEqual(EXPECTED[fixture]);
    expect(scope.filter(f => f.checkId === 'AST-SCOPE-001')).toEqual([]);
    // Declaring its permissions costs the skill no governance finding.
    const grantLines = EXPECTED[fixture].map(g => g[2]);
    expect(await governanceRows(md)).toEqual(await governanceRows(withoutLines(md, grantLines)));
  });

  describe('through the whole AST scan', () => {
    it.each(Object.keys(EXPECTED))('%s: no grant line carries a HIGH or CRITICAL finding', async fixture => {
      const d = tempDir('hma-471-');
      await writeFile(path.join(d, 'SKILL.md'), fs.readFileSync(path.join(dir, fixture)));
      const { astFindings } = await runNanoMindScan(d, []);
      const grantLines = new Set(EXPECTED[fixture].map(g => g[2]));
      expect(
        astFindings.filter(
          f => !f.passed && f.line !== undefined && grantLines.has(f.line) && (f.severity === 'high' || f.severity === 'critical'),
        ),
      ).toEqual([]);
      expect(astFindings.filter(f => f.checkId === 'AST-SCOPE-001')).toEqual([]);
    });
  });
});
