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
 * the new-user test reproduced and for one check whose findings carry a fix.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { assertDistFresh, assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { explainBody } from '../../src/explain-registry';

beforeAll(assertDistFreshIfPresent);

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

  it('explain DEP-004 prints the fix its finding carries', () => {
    const { code, stdout } = runExplain('DEP-004');
    expect(stdout).toContain('Dangerous npm Scripts');
    expect(stdout).toMatch(/Fix: Remove the curl\|sh or wget\|sh pattern from package\.json scripts/);
    expect(code).toBe(0);
  });
});
