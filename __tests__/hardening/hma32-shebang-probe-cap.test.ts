/**
 * HMA-32 — a 2-byte shebang probe, a shared 200 probe cap, and a disclosed
 * truncation.
 *
 * At base e340dcd `startsWithShebang` read the WHOLE file to answer a yes/no
 * question `execve` answers on 2 bytes, and `findSkillBundleFiles` probed every
 * extensionless file below a skill directory with no bound but the
 * admitted-count break — 250 junk files meant 250 whole-file reads, and a cap
 * that never spoke meant a payload stuffed behind junk left the `skill`
 * category reading clean.
 *
 * The recorder here spies on the tracked `fs` namespace the scanner imports
 * (`src/hardening/tracked-fs.ts`) — the seat pinned that spy target so the
 * probe cannot bypass confinement or coverage attribution. It also pins
 * `readdir` order by name, so "the payload sorts after the junk" is a fact of
 * the fixture rather than of the filesystem.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import { summarizeCoverage } from '../../src/hardening/coverage-ledger';
import { fs as trackedFs } from '../../src/hardening/tracked-fs';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { readFileSync } from 'fs';
import { BUNDLE_SKILL_MD, BUNDLE_INSTALL } from '../helpers/hma07-skill-fixtures';

const SCANNER_SOURCE_PATH = path.resolve(__dirname, '../../src/hardening/scanner.ts');
const COMMITTED_FIXTURE = path.resolve(__dirname, '../../test-fixtures/hma32-skill-bundle');

type Finding = {
  checkId: string;
  passed: boolean;
  message?: string;
  evidence?: { kind: string; lines?: Array<{ n: number; content: string; why: string }> };
};

type Truncation = { layer: string; cap: number; prefixes: string[]; reason: string };

type ScanResult = {
  allFindings?: Finding[];
  findings: Finding[];
  coverage?: {
    executions: unknown[];
    truncations: Truncation[];
    filesReadByCategory?: Record<string, number>;
  };
};

/** Per-path totals of what the scan read: full reads, probe opens, bytes. */
type PathStats = { bytesRead: number; contentReads: number; probeOpens: number };

type Recorder = {
  statsFor(p: string): PathStats;
  restore(): void;
};

/**
 * Spy on the tracked `fs` object: `readFile` totals the bytes it returned,
 * `open` counts as a probe and its handle's `read` totals `bytesRead`, and
 * `readdir` results are sorted by name for deterministic walk order.
 */
function installRecorder(): Recorder {
  const perPath = new Map<string, PathStats>();
  const statsFor = (p: string): PathStats => {
    const key = path.resolve(p);
    let s = perPath.get(key);
    if (!s) {
      s = { bytesRead: 0, contentReads: 0, probeOpens: 0 };
      perPath.set(key, s);
    }
    return s;
  };

  const realReadFile = trackedFs.readFile;
  const realOpen = trackedFs.open;
  const realReaddir = trackedFs.readdir;
  const asFs = trackedFs as unknown as Record<string, unknown>;

  asFs.readFile = async (...args: unknown[]) => {
    const result = await (realReadFile as (...a: unknown[]) => Promise<unknown>)(...args);
    if (typeof args[0] === 'string') {
      const s = statsFor(args[0]);
      s.contentReads++;
      s.bytesRead += typeof result === 'string'
        ? Buffer.byteLength(result)
        : Buffer.isBuffer(result) ? result.length : 0;
    }
    return result;
  };

  asFs.open = async (...args: unknown[]) => {
    const handle = await (realOpen as (...a: unknown[]) => Promise<unknown>)(...args) as Record<string, unknown>;
    if (typeof args[0] !== 'string') return handle;
    const s = statsFor(args[0]);
    s.probeOpens++;
    return new Proxy(handle, {
      get(target, prop) {
        if (prop === 'read') {
          return async (...rargs: unknown[]) => {
            const res = await (target.read as (...a: unknown[]) => Promise<{ bytesRead?: number }>)
              .apply(target, rargs);
            s.bytesRead += res?.bytesRead ?? 0;
            return res;
          };
        }
        const v = target[prop as string];
        return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    });
  };

  asFs.readdir = async (...args: unknown[]) => {
    const entries = await (realReaddir as (...a: unknown[]) => Promise<unknown>)(...args);
    if (Array.isArray(entries)) {
      entries.sort((a, b) => {
        const an = typeof a === 'string' ? a : (a as { name?: string })?.name ?? '';
        const bn = typeof b === 'string' ? b : (b as { name?: string })?.name ?? '';
        return an < bn ? -1 : an > bn ? 1 : 0;
      });
    }
    return entries;
  };

  return {
    statsFor,
    restore() {
      asFs.readFile = realReadFile;
      asFs.open = realOpen;
      asFs.readdir = realReaddir;
    },
  };
}

async function writeFile(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content);
}

/** A file whose stat size is `size` without `size` bytes on disk (sparse). */
async function writeSparse(filePath: string, head: string, size: number): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const fh = await fs.open(filePath, 'w');
  try {
    await fh.write(head);
    await fh.truncate(size);
  } finally {
    await fh.close();
  }
}

async function scan(targetDir: string): Promise<ScanResult> {
  return await new HardeningScanner().scan({ targetDir, autoFix: false }) as unknown as ScanResult;
}

function skill006(result: ScanResult): Finding[] {
  const findings = (result.allFindings || result.findings || []);
  return findings.filter(f => !f.passed && f.checkId === 'SKILL-006' && f.evidence?.kind === 'positive');
}

function skillCategoryState(result: ScanResult): string | undefined {
  const failed = (result.allFindings || result.findings || []).filter(f => !f.passed);
  const categories = summarizeCoverage(
    (result.coverage?.executions ?? []) as never,
    (result.coverage?.truncations ?? []) as never,
    {
      observedCheckIds: failed.map(f => f.checkId),
      filesReadByCategory: result.coverage?.filesReadByCategory,
    },
  );
  return categories.find(c => c.category === 'skill')?.state;
}

const skillTruncations = (result: ScanResult): Truncation[] =>
  (result.coverage?.truncations ?? []).filter(t => t.prefixes.includes('SKILL'));

describe('HMA-32 probe size (a 1 MiB extensionless non-shebang file)', () => {
  let tempDir: string;
  let recorder: Recorder;
  let bigfile: string;
  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma32-ac1-'));
    const skillDir = path.join(tempDir, 'skills', 'doc-tools');
    await writeFile(path.join(skillDir, 'SKILL.md'), BUNDLE_SKILL_MD);
    bigfile = path.join(skillDir, 'bigfile');
    await writeFile(bigfile, 'a'.repeat(1024 * 1024));
    recorder = installRecorder();
    await scan(tempDir);
  });
  afterAll(async () => {
    recorder.restore();
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-32.AC1 discovery reads at most 2 bytes of a 1 MiB extensionless non-shebang file under a skill directory', () => {
    expect(recorder.statsFor(bigfile).bytesRead).toBeLessThanOrEqual(2);
    expect(recorder.statsFor(bigfile).contentReads).toBe(0);
  });
});

describe('HMA-32 probe cap (250 extensionless non-shebang files in one skill directory)', () => {
  let tempDir: string;
  let recorder: Recorder;
  let junk: string[];
  let result: ScanResult;
  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma32-ac2-'));
    const skillDir = path.join(tempDir, 'skills', 'doc-tools');
    await writeFile(path.join(skillDir, 'SKILL.md'), BUNDLE_SKILL_MD);
    junk = [];
    for (let i = 0; i < 250; i++) {
      const p = path.join(skillDir, `junk-${String(i).padStart(3, '0')}`);
      junk.push(p);
      await writeFile(p, 'no shebang here\n');
    }
    recorder = installRecorder();
    result = await scan(tempDir);
  });
  afterAll(async () => {
    recorder.restore();
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-32.AC2 at most 200 of the 250 extensionless files are probed — a probe is any open or read of the file', () => {
    let probes = 0;
    for (const p of junk) {
      const s = recorder.statsFor(p);
      probes += s.probeOpens + s.contentReads;
    }
    expect(probes).toBeGreaterThan(0);
    expect(probes).toBeLessThanOrEqual(200);
  });

  it('HMA-32.AC3 the fired probe cap is a truncation record: cap 200, prefixes carrying SKILL', () => {
    const t = skillTruncations(result);
    expect(t.length).toBeGreaterThan(0);
    expect(t.some(x => x.cap === 200)).toBe(true);
  });

  it('HMA-32.AC3 summarizeCoverage downgrades the skill category from examined to truncated', () => {
    expect(skillCategoryState(result)).toBe('truncated');
  });
});

describe('HMA-32 hidden-cap fixture (a payload script after 200 junk files)', () => {
  let tempDir: string;
  let recorder: Recorder;
  let result: ScanResult;
  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma32-ac3-'));
    const skillDir = path.join(tempDir, 'skills', 'doc-tools');
    await writeFile(path.join(skillDir, 'SKILL.md'), BUNDLE_SKILL_MD);
    // The recorder sorts readdir by name, so every junk-* file is walked
    // before zzz-payload and the probe budget is spent before it is reached.
    for (let i = 0; i < 250; i++) {
      await writeFile(path.join(skillDir, `junk-${String(i).padStart(3, '0')}`), 'no shebang here\n');
    }
    await writeFile(path.join(skillDir, 'zzz-payload'), BUNDLE_INSTALL);
    recorder = installRecorder();
    result = await scan(tempDir);
  });
  afterAll(async () => {
    recorder.restore();
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-32.AC3 the payload behind the cap is not admitted AND the scan says so — a truncation, never a clean skill category', () => {
    const cited = skill006(result).flatMap(f => f.evidence?.lines ?? []).map(l => l.why).join('\n');
    expect(cited).not.toContain('zzz-payload');

    const t = skillTruncations(result);
    expect(t.some(x => x.cap === 200)).toBe(true);
    expect(skillCategoryState(result)).toBe('truncated');
  });
});

describe('HMA-32 admission slice (80 admitted files across two subdirectories)', () => {
  let tempDir: string;
  let result: ScanResult;
  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma32-slice-'));
    const skillDir = path.join(tempDir, 'skills', 'doc-tools');
    await writeFile(path.join(skillDir, 'SKILL.md'), BUNDLE_SKILL_MD);
    // Two batches of 40: each subdirectory stays under the per-level break,
    // the parent accumulates 80, and the 60-file admission slice drops 20.
    for (const sub of ['a', 'b']) {
      for (let i = 0; i < 40; i++) {
        await writeFile(path.join(skillDir, sub, `s${String(i).padStart(2, '0')}.sh`), '#!/bin/sh\necho ok\n');
      }
    }
    result = await scan(tempDir);
  });
  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-32.AC3 the 60-file admission slice reports the files it drops: a truncation with cap 60 and the skill category truncated', () => {
    const t = skillTruncations(result);
    expect(t.some(x => x.cap === 60)).toBe(true);
    expect(skillCategoryState(result)).toBe('truncated');
  });
});

describe('HMA-32 committed bundle fixture (test-fixtures/hma32-skill-bundle)', () => {
  let recorder: Recorder;
  let result: ScanResult;
  const inFixture = (name: string): string => path.join(COMMITTED_FIXTURE, 'skills', 'doc-tools', name);
  beforeAll(async () => {
    recorder = installRecorder();
    result = await scan(COMMITTED_FIXTURE);
  });
  afterAll(() => {
    recorder.restore();
  });

  it('HMA-32.AC4 an admitted 64 KiB extensionless shebang file is read once plus the 2-byte probe (<= 64 KiB + 2 bytes)', () => {
    const s = recorder.statsFor(inFixture('runner'));
    expect(s.contentReads).toBe(1);
    expect(s.bytesRead).toBeLessThanOrEqual(64 * 1024 + 2);
  });

  it('HMA-32.AC5 SKILL-006 fires on the bundled shebang script with the exfiltration line, file and line intact', () => {
    const findings = skill006(result);
    expect(findings.length).toBe(1);
    const lines = findings[0].evidence?.lines ?? [];
    const cited = lines.map(l => l.why).join('\n');
    expect(cited).toContain('collect');
    expect(findings[0].message).toContain('collect');
    for (const line of lines) {
      expect(line.n).toBeGreaterThan(0);
      expect(line.content.length).toBeGreaterThan(0);
    }
  });

  it('HMA-32.AC5 the non-shebang file, the <2-byte file and the .md sibling are refused; only the shebang file is admitted', () => {
    const cited = skill006(result).flatMap(f => f.evidence?.lines ?? []).map(l => l.why).join('\n');
    expect(cited).not.toContain('NOTES');
    expect(cited).not.toContain('CHANGELOG.md');
    expect(cited).not.toContain('tiny');
    expect(cited).not.toContain('runner');

    // Under 2 bytes there is no shebang to find — the stat gate refuses before any open.
    expect(recorder.statsFor(inFixture('tiny')).contentReads).toBe(0);
    expect(recorder.statsFor(inFixture('tiny')).bytesRead).toBe(0);
  });

  it('HMA-32.AC5 no truncation fires on a real-sized bundle — the skill category is not downgraded by this fixture', () => {
    expect(skillTruncations(result)).toEqual([]);
  });
});

describe('HMA-32 size edges (over MAX_FILE_SIZE refused, 8 MiB probed at 2 bytes)', () => {
  let tempDir: string;
  let recorder: Recorder;
  let result: ScanResult;
  let oversize: string;
  let eightMiB: string;
  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma32-size-'));
    const skillDir = path.join(tempDir, 'skills', 'doc-tools');
    await writeFile(path.join(skillDir, 'SKILL.md'), BUNDLE_SKILL_MD);
    // A shebang and a payload line, then sparse-extended past MAX_FILE_SIZE:
    // if the size gate ever stopped refusing it, SKILL-006 would cite it.
    oversize = path.join(skillDir, 'oversize');
    await writeSparse(oversize, BUNDLE_INSTALL, 11 * 1024 * 1024);
    eightMiB = path.join(skillDir, 'eight-mib');
    await writeSparse(eightMiB, 'xx', 8 * 1024 * 1024);
    recorder = installRecorder();
    result = await scan(tempDir);
  });
  afterAll(async () => {
    recorder.restore();
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-32.AC5 a file over MAX_FILE_SIZE is refused without being opened', () => {
    const cited = skill006(result).flatMap(f => f.evidence?.lines ?? []).map(l => l.why).join('\n');
    expect(cited).not.toContain('oversize');
    expect(recorder.statsFor(oversize).probeOpens).toBe(0);
    expect(recorder.statsFor(oversize).contentReads).toBe(0);
  });

  it('HMA-32.AC6 an 8 MiB extensionless non-shebang file is probed at exactly 2 bytes — opened, not silently size-refused', () => {
    const s = recorder.statsFor(eightMiB);
    expect(s.probeOpens).toBe(1);
    expect(s.contentReads).toBe(0);
    expect(s.bytesRead).toBe(2);
  });
});

describe('HMA-32 static shape of the fix', () => {
  const source = readFileSync(SCANNER_SOURCE_PATH, 'utf-8');

  it('HMA-32.AC6 startsWithShebang holds no whole-file read', () => {
    const fn = source.match(/private async startsWithShebang[\s\S]*?\n {2}\}\n/);
    expect(fn).not.toBeNull();
    expect(fn![0]).not.toContain('readFile');
  });

  it('HMA-32.AC2 the 200 cap is ONE constant, shared with checkNemoClawPatterns; the local maxFiles is gone', () => {
    expect((source.match(/= 200;/g) ?? []).length).toBe(1);
    expect(source).toContain('const MAX_FILES_PER_LAYER = 200;');
    expect(source).not.toContain('maxFiles = 200');
  });

  it('HMA-32.AC6 every unrelated cap is unchanged and no new coverage.truncate site exists beyond the ruled-in ones', () => {
    expect(source).toContain('const SKILL_BUNDLE_MAX_DEPTH = 4;');
    expect(source).toContain('const SKILL_BUNDLE_MAX_FILES = 60;');
    expect(source).toContain('const SKILL_BUNDLE_MAX_DIRS = 40;');
    expect(source).toContain('const MAX_FILE_SIZE = 10 * 1024 * 1024;');
    // Base's two call sites (nemo-source, decode) plus the two AC3 ruled in
    // (the skill probe cap and the 60-file admission slice).
    expect((source.match(/this\.coverage\.truncate\(/g) ?? []).length).toBe(4);
  });
});

describe('HMA-32 the NEMO cap still discloses through the shared constant', () => {
  let tempDir: string;
  let result: ScanResult;
  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma32-nemo-'));
    for (let i = 0; i < 201; i++) {
      await writeFile(path.join(tempDir, 'src', `s${String(i).padStart(3, '0')}.sh`), 'echo ok\n');
    }
    result = await scan(tempDir);
  });
  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('HMA-32.AC6 201 .sh files still emit the nemo-source truncation with cap 200 and prefixes NEMO', () => {
    const t = (result.coverage?.truncations ?? []).find(x => x.layer === 'nemo-source');
    expect(t).toBeDefined();
    expect(t!.cap).toBe(200);
    expect(t!.prefixes).toEqual(['NEMO']);
  });
});
