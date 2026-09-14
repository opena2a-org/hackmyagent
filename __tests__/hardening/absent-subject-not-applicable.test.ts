/**
 * #458 — an absent check subject is a not-applicable record, not a failure.
 *
 * PROMPT-001, SANDBOX-002 and TOOL-001 measured a SUBSTANCE ("boundary
 * markers present", "runs as non-root", "tools whitelisted") but emitted
 * `passed: false` when the SUBJECT (CLAUDE.md, Dockerfile, mcp.json) did not
 * exist — collapsing "there is nothing to measure" with "it was measured and
 * found wanting". The ruled contract (COUNCIL_LEDGER #458):
 *
 *   read   -> measured pass/fail, byte-identical to before;
 *   absent -> a `notApplicable: { subject, reason }` record with NO severity
 *             and `passed` omitted, carried on `allFindings` only (the render
 *             channel `findings` never shows it);
 *   unread -> NO record at all: any errno other than not-there (EACCES,
 *             EPERM, ELOOP, ...) is an unread input, and the ledger's
 *             unreadable-inputs channel (SCAN-UNREAD-001) discloses it.
 *             Emitting NA there would let a permission error look like
 *             a clean "nothing to measure" (#438/#499/#508/#514).
 *
 * SANDBOX-001 is the ruled exception: containerization is a mitigation the
 * check RECOMMENDS, so its absence IS the finding — the fail keeps
 * `passed: false` and gains `file: 'Dockerfile'` (the path the fix creates,
 * GIT-001's advisory shape).
 *
 * Fixtures are mcp-typed on purpose: the prefix map scopes 'PROMPT-' to
 * mcp/api, 'TOOL-' to mcp, 'SANDBOX-' to webapp/api/mcp, and
 * `dropPathlessNoiseFloor` routes NA records (no `passed`, no `file`) through
 * `findingAppliesTo` like any pathless record. Only an mcp tree keeps all
 * three NA records in `allFindings`; the cli-tree block pins the inversion.
 *
 * `notApplicable.subject`/`.reason` are emitter literals — fixed strings in
 * the check's source, never scanned bytes — which is what keeps them outside
 * `BYTE_CARRYING_FIELDS` (finding-emit.ts). The exact-subject assertions here
 * pin that the values are the ruled constants, not derived content.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { HardeningScanner, findingAppliesTo } from '../../src/hardening/scanner';
import type { SecurityFinding, SecurityFindingDraft, ScanResult } from '../../src/hardening/security-check';
import { initThrowawayRepo } from '../helpers/throwaway-repo';

const SCAN_TIMEOUT = 120_000;

const runsAsRoot = typeof process.getuid === 'function' && process.getuid() === 0;

const tempDirs: string[] = [];

async function makeTree(
  kind: 'mcp' | 'cli',
  files: Record<string, string> = {},
): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-test-'));
  tempDirs.push(dir);
  const pkg: Record<string, unknown> =
    kind === 'mcp'
      ? { name: 'na-fixture', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.0.0' } }
      : { name: 'plain-tool', version: '1.0.0', bin: { pt: './index.js' } };
  await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2));
  for (const [rel, content] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
    await fs.writeFile(path.join(dir, rel), content);
  }
  initThrowawayRepo(dir);
  return dir;
}

async function scanTree(dir: string): Promise<ScanResult> {
  const scanner = new HardeningScanner();
  return scanner.scan({ targetDir: dir });
}

function byId(findings: SecurityFinding[] | undefined, checkId: string): SecurityFinding[] {
  return (findings ?? []).filter((f) => f.checkId === checkId);
}

afterAll(async () => {
  for (const dir of tempDirs) {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

describe('#458 — absent subjects on an mcp tree (the pin)', () => {
  let result: ScanResult;

  beforeAll(async () => {
    // mcp-typed tree with NO CLAUDE.md, NO Dockerfile/compose, NO mcp.json.
    result = await scanTree(await makeTree('mcp'));
  }, SCAN_TIMEOUT);

  const NA_CELLS: Array<[string, string]> = [
    ['PROMPT-001', 'CLAUDE.md'],
    ['SANDBOX-002', 'Dockerfile'],
    // #637 — the subject is the SET of root spellings the check reads.
    ['TOOL-001', 'mcp.json or .mcp.json'],
    // The non-census sites converted in the same unit: each reads ONE subject
    // through readCheckSubject / readCheckDir, so the same three-way contract
    // holds. The subject strings are the emitter literals.
    ['CLAUDE-004', '.claude/settings.json'],
    ['CLAUDE-005', '.claude/settings.json'],
    ['CLAUDE-006', 'CLAUDE.md'],
    ['CLAUDE-007', '.claude/settings.json'],
    ['CURSOR-001', 'Cursor rules (.cursor/rules, .cursorrules)'],
    ['VSCODE-001', '.vscode/mcp.json'],
    ['VSCODE-002', '.vscode/mcp.json'],
  ];

  // Hazard probes (PERM-001/002/003, LOG-003) stat a fixed list of paths for a
  // DANGEROUS state (world-readable log, executable config, ...). A not-there
  // errno on every probe is a completed measurement — the hazard is absent —
  // so these keep `passed: true`; they never emit not-applicable.
  const HZ_PASS_CELLS = ['PERM-001', 'PERM-002', 'PERM-003', 'LOG-003'];

  it.each(NA_CELLS)(
    '%s emits exactly one not-applicable record naming %s, with no severity and passed omitted',
    (checkId, subject) => {
      const records = byId(result.allFindings, checkId);
      expect(records).toHaveLength(1);
      const f = records[0];
      expect(f.notApplicable?.subject).toBe(subject);
      expect(f.notApplicable?.reason).toBeTruthy();
      // NO severity: an NA record carries no judgment weight. `?? 0` in the
      // score map and the NA-first guards depend on this staying absent.
      expect(f.severity).toBeUndefined();
      // `passed` OMITTED — not `false` (that was the defect) and not `true`
      // (mcp-server's old `.get(id) !== false` would read it as a pass).
      expect(Object.prototype.hasOwnProperty.call(f, 'passed')).toBe(false);
    },
  );

  it('the render channel never shows a not-applicable record', () => {
    expect(result.findings.filter((f) => f.notApplicable)).toHaveLength(0);
    for (const [checkId] of NA_CELLS) {
      expect(byId(result.findings, checkId)).toHaveLength(0);
    }
  });

  it.each(HZ_PASS_CELLS)(
    '%s keeps its measured pass on a tree with none of its probed paths — absence of a hazard is a verdict, not a missing subject',
    (checkId) => {
      const records = byId(result.allFindings, checkId);
      expect(records).toHaveLength(1);
      expect(records[0].passed).toBe(true);
      expect(records[0].severity).toBeDefined();
      expect(records[0].notApplicable).toBeUndefined();
    },
  );

  it('SANDBOX-001 keeps the absent-mitigation advisory: passed false with file naming the path the fix creates', () => {
    const records = byId(result.allFindings, 'SANDBOX-001');
    expect(records).toHaveLength(1);
    expect(records[0].passed).toBe(false);
    expect(records[0].file).toBe('Dockerfile');
    expect(records[0].notApplicable).toBeUndefined();
    // And it IS user-facing — the advisory renders.
    expect(byId(result.findings, 'SANDBOX-001').some((f) => f.passed === false)).toBe(true);
  });
});

describe('#458 G3 — a present subject is still measured in both directions', () => {
  let passing: ScanResult;
  let failing: ScanResult;

  beforeAll(async () => {
    passing = await scanTree(
      await makeTree('mcp', {
        'CLAUDE.md': 'SYSTEM:\nAgent instructions live here.\n',
        Dockerfile: 'FROM node:20\nUSER app\n',
        'mcp.json': JSON.stringify({ servers: { srv: { allowedTools: ['read'] } } }),
      }),
    );
    // The failing subjects avoid every pass-predicate substring:
    // CLAUDE.md has none of SYSTEM:/USER:/---/###/the two phrases;
    // Dockerfile has no USER directive; mcp.json has no allowedTools.
    failing = await scanTree(
      await makeTree('mcp', {
        'CLAUDE.md': 'plain agent notes\nnothing marks a boundary here\n',
        Dockerfile: 'FROM node:20\nCMD ["node","index.js"]\n',
        'mcp.json': JSON.stringify({ servers: { srv: { command: 'node' } } }),
      }),
    );
  }, SCAN_TIMEOUT * 2);

  it.each(['PROMPT-001', 'SANDBOX-002', 'TOOL-001'])(
    '%s measures a compliant subject as a pass with severity and no notApplicable',
    (checkId) => {
      const records = byId(passing.allFindings, checkId);
      expect(records).toHaveLength(1);
      expect(records[0].passed).toBe(true);
      expect(records[0].severity).toBeDefined();
      expect(records[0].notApplicable).toBeUndefined();
    },
  );

  it.each(['PROMPT-001', 'SANDBOX-002', 'TOOL-001'])(
    '%s measures a non-compliant subject as a fail with severity and no notApplicable',
    (checkId) => {
      const records = byId(failing.allFindings, checkId);
      expect(records).toHaveLength(1);
      expect(records[0].passed).toBe(false);
      expect(records[0].severity).toBeDefined();
      expect(records[0].notApplicable).toBeUndefined();
    },
  );

  it('SANDBOX-001 passes when containerization is present, without the advisory file', () => {
    const records = byId(passing.allFindings, 'SANDBOX-001');
    expect(records).toHaveLength(1);
    expect(records[0].passed).toBe(true);
    expect(records[0].file).toBeUndefined();
  });
});

describe('#458 — a present-but-unparseable subject is a read subject, not a missing one', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await scanTree(
      await makeTree('mcp', { 'mcp.json': '{nope', '.claude/settings.json': '{nope' }),
    );
  }, SCAN_TIMEOUT);

  it('TOOL-001 keeps the fail: the subject exists, its state was measured', () => {
    const records = byId(result.allFindings, 'TOOL-001');
    expect(records).toHaveLength(1);
    expect(records[0].passed).toBe(false);
    expect(records[0].notApplicable).toBeUndefined();
  });

  it('CLAUDE-004 keeps its pass with the parse-failure message: the settings file was read', () => {
    // Pre-#458 behaviour, byte-identical: an unparseable settings file is
    // reported, not scored against. What #458 changed is only that a MISSING
    // file no longer takes this branch.
    const records = byId(result.allFindings, 'CLAUDE-004');
    expect(records).toHaveLength(1);
    expect(records[0].passed).toBe(true);
    expect(records[0].message).toBe('Claude settings file could not be parsed');
    expect(records[0].notApplicable).toBeUndefined();
  });

  it.each(['CLAUDE-005', 'CLAUDE-007'])('%s emits a measured record, never not-applicable, for the same read subject', (checkId) => {
    const records = byId(result.allFindings, checkId);
    expect(records).toHaveLength(1);
    expect(typeof records[0].passed).toBe('boolean');
    expect(records[0].notApplicable).toBeUndefined();
  });
});

describe.skipIf(runsAsRoot)('#458 — an unreadable subject emits nothing; the unread channel discloses it', () => {
  let result: ScanResult;

  beforeAll(async () => {
    const dir = await makeTree('mcp', {
      'CLAUDE.md': 'SYSTEM:\nwould pass, if it were readable\n',
      Dockerfile: 'FROM node:20\nUSER app\n',
    });
    await fs.chmod(path.join(dir, 'CLAUDE.md'), 0o000);
    await fs.chmod(path.join(dir, 'Dockerfile'), 0o000);
    // Precondition, asserted LOUDLY: if these are readable anyway (exotic
    // filesystem, elevated process), the cells below would measure nothing —
    // a fixture precondition that cannot be met must fail, not skip green.
    await expect(fs.readFile(path.join(dir, 'CLAUDE.md'), 'utf-8')).rejects.toMatchObject({ code: 'EACCES' });
    result = await scanTree(dir);
  }, SCAN_TIMEOUT);

  it.each(['PROMPT-001', 'PROMPT-002', 'PROMPT-003', 'PROMPT-004', 'CLAUDE-006'])(
    '%s emits no record at all — neither measured nor not-applicable',
    (checkId) => {
      // Every check whose subject is CLAUDE.md, not only the one #458 named:
      // the EACCES must not leak through any of them as a verdict.
      expect(byId(result.allFindings, checkId)).toHaveLength(0);
      expect(byId(result.findings, checkId)).toHaveLength(0);
    },
  );

  it('SANDBOX-001 and SANDBOX-002 emit nothing when the Dockerfile probe is obstructed', () => {
    // Dockerfile unread + composes absent: containerization is UNKNOWN, not
    // absent — an NA or a fail here would classify an EACCES as a verdict.
    expect(byId(result.allFindings, 'SANDBOX-001')).toHaveLength(0);
    expect(byId(result.allFindings, 'SANDBOX-002')).toHaveLength(0);
  });

  it('the genuinely absent subject still gets its NA record in the same scan', () => {
    // mcp.json really is not there: mixed per-subject states must not bleed
    // into each other.
    const records = byId(result.allFindings, 'TOOL-001');
    expect(records).toHaveLength(1);
    expect(records[0].notApplicable?.subject).toBe('mcp.json or .mcp.json');
  });

  it('SCAN-UNREAD-001 names both obstructed subjects', () => {
    const unread = byId(result.allFindings, 'SCAN-UNREAD-001');
    const named = (rel: string) =>
      unread.some((f) => f.file === rel || (f.message ?? '').includes(rel));
    expect(named('CLAUDE.md')).toBe(true);
    expect(named('Dockerfile')).toBe(true);
  });
});

describe('#458 — a hazard probe that cannot stat its path withholds its verdict; a hazard measured elsewhere still fails', () => {
  // `fs.stat` follows symlinks, so a self-referential link raises ELOOP — an
  // errno that is NOT not-there, on a filesystem state any user can create
  // (no chmod, so this describe does not skip under root). `.env` sits on the
  // probe lists of PERM-001, PERM-002 and PERM-003; `app.log` on LOG-003's.
  let withheld: ScanResult;
  let measured: ScanResult;

  beforeAll(async () => {
    const loopTree = await makeTree('mcp');
    await fs.symlink('.env', path.join(loopTree, '.env'));
    await fs.symlink('app.log', path.join(loopTree, 'app.log'));
    // Precondition, asserted LOUDLY: the probe must fail with ELOOP here, or
    // the cells below would measure nothing.
    await expect(fs.stat(path.join(loopTree, '.env'))).rejects.toMatchObject({ code: 'ELOOP' });
    await expect(fs.stat(path.join(loopTree, 'app.log'))).rejects.toMatchObject({ code: 'ELOOP' });
    withheld = await scanTree(loopTree);

    // Same obstruction, plus a hazard the probe CAN see on another listed
    // path: secrets.json world-readable and group-writable.
    const hazardTree = await makeTree('mcp', { 'secrets.json': '{}\n' });
    await fs.symlink('.env', path.join(hazardTree, '.env'));
    await fs.chmod(path.join(hazardTree, 'secrets.json'), 0o666);
    measured = await scanTree(hazardTree);
  }, SCAN_TIMEOUT * 2);

  it.each(['PERM-001', 'PERM-002', 'PERM-003', 'LOG-003'])(
    '%s emits no record when a probed path raised ELOOP and no hazard was measured',
    (checkId) => {
      expect(byId(withheld.allFindings, checkId)).toHaveLength(0);
      expect(byId(withheld.findings, checkId)).toHaveLength(0);
    },
  );

  it('SCAN-UNREAD-001 names both looped paths — stat failures are ledgered by the check itself', () => {
    const unread = byId(withheld.allFindings, 'SCAN-UNREAD-001');
    const named = (rel: string) =>
      unread.some((f) => f.file === rel || (f.message ?? '').includes(rel));
    expect(named('.env')).toBe(true);
    expect(named('app.log')).toBe(true);
  });

  it.each(['PERM-001', 'PERM-003'])(
    '%s still fails when the hazard was measured on a path the probe could stat',
    (checkId) => {
      // The withheld verdict is "nothing measured", not "unread wins": a
      // measured hazard is disclosed regardless of the obstructed sibling.
      const records = byId(measured.allFindings, checkId);
      expect(records).toHaveLength(1);
      expect(records[0].passed).toBe(false);
      expect(records[0].notApplicable).toBeUndefined();
    },
  );

  it('PERM-002 still emits nothing on the hazard tree: its only present probe path is the looped one', () => {
    expect(byId(measured.allFindings, 'PERM-002')).toHaveLength(0);
  });
});

describe('#458 — NA records are project-type-scoped like any pathless record', () => {
  it(
    'a cli tree with no subjects keeps NA records only for checks that apply to cli',
    async () => {
      // 'PROMPT-' -> mcp/api, 'TOOL-' -> mcp, 'SANDBOX-' -> webapp/api/mcp:
      // none includes cli, so dropPathlessNoiseFloor routes those NA records
      // out of allFindings exactly as it routes any other pathless record.
      // Checks scoped 'all' (CRED-, PERM-, CLAUDE-, ...) keep theirs, so the
      // cell is stated as the predicate, not as a count of zero. Absence of
      // the check on non-applicable trees is #426's lane — this pins that
      // #458 did not change it.
      const result = await scanTree(await makeTree('cli'));
      const na = (result.allFindings ?? []).filter((f) => f.notApplicable);
      expect(na.length).toBeGreaterThan(0);
      for (const f of na) {
        expect(findingAppliesTo(f as SecurityFindingDraft, 'cli'), `${f.checkId} does not apply to a cli tree`).toBe(true);
      }
      for (const checkId of ['PROMPT-001', 'SANDBOX-002', 'TOOL-001']) {
        expect(byId(result.allFindings, checkId)).toHaveLength(0);
      }
    },
    SCAN_TIMEOUT,
  );
});
