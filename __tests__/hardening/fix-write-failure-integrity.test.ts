// A fix write that fails must never improve the report.
//
// Every auto-fix write was a bare `await fs.writeFile` sitting inside the
// same `try` as its own `findings.push`, under a `catch` written to mean
// "this config file isn't here". So on an unwritable target the write threw
// straight past the push and the finding was never created — not downgraded,
// not marked unverified, absent. The scan then scored as though the issue had
// never been detected.
//
// Measured on an MCP project with an unwritable `mcp.json`:
//
//   secure          MCP-001 HIGH, score  69/100 (clamped from 89)
//   secure --fix    no finding,   score 100/100, config still scoped at "/"
//
// Running `--fix` scored BETTER than not running it, on a tree it had failed
// to repair, with the vulnerability still on disk. That is the worst possible
// direction for a security scanner and it inverts the tool's core promise.
//
// Two independent causes, both covered here:
//
//  1. The write threw past the push. Fix writes now go through
//     `applyFixWrite`, which returns false instead of throwing, so the check
//     always reports and reports the truth.
//  2. `countsAgainstScore` returned early on `passed`. Twelve checks report
//     `passed: <check>Fixed`, flipping `passed` true the moment they apply a
//     fix, so the unverified-fix branch was unreachable for all of them —
//     only `PERM-001`'s shape was ever covered.

import { describe, it, expect, afterEach } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { countsAgainstScore } from '../../src/ui/verdict-band';

const ROOT_SCOPED_MCP =
  '{"servers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}';
// An MCP-typed project, so MCP-001 survives the project-type relevance gate
// and reaches the user-facing findings list and the score.
const MCP_PKG = JSON.stringify({
  name: 'h',
  version: '1.0.0',
  dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' },
});

const locked: string[] = [];
const dirs: string[] = [];

/** macOS immutable flag — a real EPERM on write, not a mocked one. */
function lock(p: string) {
  execSync(`chflags uchg ${JSON.stringify(p)}`);
  locked.push(p);
}

function mcpFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-fixwrite-'));
  dirs.push(dir);
  execSync('git init -q .', { cwd: dir });
  writeFileSync(join(dir, 'package.json'), MCP_PKG);
  writeFileSync(join(dir, 'mcp.json'), ROOT_SCOPED_MCP);
  return dir;
}

afterEach(() => {
  for (const p of locked.splice(0)) {
    try { execSync(`chflags nouchg ${JSON.stringify(p)}`); } catch { /* already gone */ }
  }
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const darwin = process.platform === 'darwin';

describe('a failed fix write cannot improve the report', { timeout: 120_000 }, () => {
  it.runIf(darwin)('keeps the finding when the fix write throws', async () => {
    const dir = mcpFixture();
    const cfg = join(dir, 'mcp.json');

    const before = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const beforeFinding = before.findings.find(f => f.checkId === 'MCP-001');

    // Guard the fixture: if MCP-001 stops firing without --fix, everything
    // below is vacuous.
    expect(beforeFinding, 'MCP-001 did not fire — fixture no longer triggers it').toBeDefined();
    expect(before.projectType).toBe('mcp');

    lock(cfg);
    const after = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const afterFinding = after.findings.find(f => f.checkId === 'MCP-001');

    // The write genuinely failed: the config is untouched on disk.
    expect(readFileSync(cfg, 'utf8'), 'the fixture became writable').toBe(ROOT_SCOPED_MCP);

    // Pre-fix this was `undefined` — the finding was erased outright.
    expect(afterFinding, 'MCP-001 was erased by a failed fix write').toBeDefined();
    expect(afterFinding!.passed).toBe(false);
    expect(afterFinding!.fixed).toBeFalsy();
  });

  it.runIf(darwin)('never scores a failed --fix better than no --fix', async () => {
    const dir = mcpFixture();
    const cfg = join(dir, 'mcp.json');

    const before = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    lock(cfg);
    const after = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(readFileSync(cfg, 'utf8'), 'the fixture became writable').toBe(ROOT_SCOPED_MCP);

    // Pre-fix: 69 -> 100. Repairing nothing must never raise the score.
    expect(after.score).toBeLessThanOrEqual(before.score);
    expect(after.score).toBeLessThan(70);
  });

  it.runIf(darwin)('leaves the verdict fail-direction when nothing was repaired', async () => {
    const dir = mcpFixture();
    lock(join(dir, 'mcp.json'));

    const after = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(after.findings.some(f => countsAgainstScore(f) && f.severity === 'high')).toBe(true);
  });
});

// The first version of this file tested MCP-001 and nothing else, and stayed
// green while four other CRITICAL-severity checks had the identical defect —
// CRED-001, LLM-00x and AITOOL-00x erased their finding, WEBCRED-001 and
// SKILL-004 reported `passed: true` for a write that never landed, and
// SKILL-001/004 threw out of the whole scan (raw EPERM on stderr, zero
// findings for the entire tree). One check is not a class.
const FIX_WRITE_CHECKS: { name: string; file: string; body: string; expect: string }[] = [
  {
    name: 'CRED-001',
    file: 'config.json',
    body: '{"anthropic":"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}',
    expect: 'CRED-001',
  },
  {
    name: 'LLM-00x',
    file: 'docker-compose.yml',
    body: 'services:\n  vllm:\n    command: --host 0.0.0.0 --port 8000\n',
    expect: 'LLM-',
  },
  {
    name: 'AITOOL-00x',
    file: 'app.py',
    body: 'import gradio as gr\ndemo.launch(share=True)\n',
    expect: 'AITOOL-',
  },
];

describe.runIf(darwin)('the whole fix-write class, not just one check', { timeout: 180_000 }, () => {
  for (const c of FIX_WRITE_CHECKS) {
    it(`${c.name}: keeps its finding and does not raise the score`, async () => {
      const dir = mkdtempSync(join(tmpdir(), 'hma-fixclass-'));
      dirs.push(dir);
      execSync('git init -q .', { cwd: dir });
      writeFileSync(join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
      const target = join(dir, c.file);
      writeFileSync(target, c.body);

      const before = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
      const hitBefore = before.findings.filter(f => f.checkId.startsWith(c.expect));
      expect(hitBefore.length, `${c.name} did not fire — fixture is inert`).toBeGreaterThan(0);

      lock(target);
      const after = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

      expect(readFileSync(target, 'utf8'), 'the fixture became writable').toBe(c.body);

      const hitAfter = after.findings.filter(f => f.checkId.startsWith(c.expect));
      expect(hitAfter.length, `${c.name} was erased by a failed fix write`).toBe(hitBefore.length);
      expect(hitAfter.every(f => !f.passed), `${c.name} claims passed for an unwritten fix`).toBe(true);
      expect(after.score, `${c.name}: failed --fix scored better than no --fix`)
        .toBeLessThanOrEqual(before.score);
    });
  }

  it('SKILL-001/004: an unwritable skill file does not abort the scan', async () => {
    // These two had no enclosing try at all, so the throw escaped `scan()`
    // and the user got a raw EPERM and no scan of any kind.
    const dir = mkdtempSync(join(tmpdir(), 'hma-fixclass-'));
    dirs.push(dir);
    execSync('git init -q .', { cwd: dir });
    writeFileSync(join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    mkdirSync(join(dir, 'skills', 'demo'), { recursive: true });
    const skill = join(dir, 'skills', 'demo', 'SKILL.md');
    const body = '---\nname: demo\ncapabilities:\n  - filesystem: *\n---\n# Demo\n';
    writeFileSync(skill, body);

    const before = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    expect(before.findings.some(f => f.checkId === 'SKILL-004')).toBe(true);

    lock(skill);
    // Pre-fix this rejected with EPERM instead of resolving.
    const after = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(readFileSync(skill, 'utf8')).toBe(body);
    expect(after.findings.length, 'the scan produced nothing').toBeGreaterThan(0);
    const s4 = after.findings.filter(f => f.checkId === 'SKILL-004');
    expect(s4.length, 'SKILL-004 was erased').toBeGreaterThan(0);
    expect(s4.every(f => !f.passed)).toBe(true);
  });

  it('tells the user a fix write failed instead of failing silently', async () => {
    // Revoking the flag alone left an ordinary unfixed finding whose remedy
    // was `secure --fix` — the command that had just silently failed.
    const dir = mkdtempSync(join(tmpdir(), 'hma-fixclass-'));
    dirs.push(dir);
    execSync('git init -q .', { cwd: dir });
    writeFileSync(join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    const target = join(dir, 'config.json');
    writeFileSync(target, '{"anthropic":"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}');

    lock(target);
    const after = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    const disclosure = after.findings.find(f => f.checkId === 'FIX-WRITE-FAILED');
    expect(disclosure, 'a failed fix write was never disclosed').toBeDefined();
    expect(disclosure!.message).toContain('config.json');
    expect(disclosure!.fix ?? '').not.toBe('hackmyagent secure --fix');
  });
});

describe('countsAgainstScore reaches optimistic-passed checks', () => {
  // The ordering bug in isolation. Twelve checks report `passed: <x>Fixed`,
  // so they arrive here as `passed: true, fixed: true`. With the `passed`
  // test first, the unverified branch below was dead code for all of them.
  it('counts an unverified fix that the check reported as passed', () => {
    expect(countsAgainstScore({ passed: true, fixed: true, fixVerified: false })).toBe(true);
  });

  it('still excludes a fix that was verified', () => {
    expect(countsAgainstScore({ passed: true, fixed: true, fixVerified: true })).toBe(false);
  });

  it('still excludes an ordinary passing check', () => {
    expect(countsAgainstScore({ passed: true })).toBe(false);
    expect(countsAgainstScore({ passed: true, fixed: false })).toBe(false);
  });

  it('still counts an ordinary failing check', () => {
    expect(countsAgainstScore({ passed: false })).toBe(true);
    expect(countsAgainstScore({ passed: false, fixed: false })).toBe(true);
  });

  it('still excludes a fix awaiting verification', () => {
    // `fixVerified` unset means the verification pass has not run, which is
    // not the same as proven-failed. Only an explicit false counts.
    expect(countsAgainstScore({ passed: false, fixed: true })).toBe(false);
  });
});
