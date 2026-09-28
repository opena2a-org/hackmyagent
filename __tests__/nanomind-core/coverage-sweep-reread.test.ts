/**
 * #520 — the coverage sweep must not re-read an already-read file through the
 * tracked namespace.
 *
 * `compiled` candidates are pushed only after the compile loop's tracked read
 * resolved. The sweep read every candidate again through tracked fs, outside
 * any `coverage.run()` frame, so a read that failed in the window between the
 * two recorded an unread input that no later read could subtract: exit 2 and a
 * `chmod` remedy naming a file the run had read.
 *
 * The failure is injected, not raced: the candidate's file is made unreadable
 * on disk (what a tracked re-read would hit), and the off-ledger re-read the
 * bridge hands the sweep is replaced by one that reports the same loss.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCoverageSweep } from '../../src/nanomind-core/orchestrate';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import type { CoverageCandidate } from '../../src/nanomind-core/scanner-bridge';
import type { ArtifactCoverageVerdict } from '../../src/nanomind-core/inference/security-analyst';
import { CoverageLedger, withActiveLedger } from '../../src/hardening/coverage-ledger';

const benign: ArtifactCoverageVerdict = {
  attackClass: 'none',
  classification: 'benign',
  severity: 'info',
  confidence: 0.95,
  source: 'nlm',
  analysis: 'No attack content.',
  evidence: '',
  modelVersion: 'test',
} as ArtifactCoverageVerdict;

// chmod 000 does not stop root, and Windows has no mode bits to clear.
const canMakeUnreadable = process.platform !== 'win32' && process.getuid?.() !== 0;

describe.skipIf(!canMakeUnreadable)('#520 coverage sweep re-reads compiled candidates off the ledger', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'hma-520-'));
    await writeFile(join(dir, 'SKILL.md'), '# skill\n\nSummarise the file the user names.\n');
    await chmod(join(dir, 'SKILL.md'), 0o000);
  });

  afterEach(async () => {
    await chmod(join(dir, 'SKILL.md'), 0o644).catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  });

  it('a compiled candidate whose re-read fails records no unread input and is skipped', async () => {
    const ledger = new CoverageLedger(dir);
    const read: string[] = [];
    const candidates: CoverageCandidate[] = [{ path: 'SKILL.md', artifactType: 'skill', provenance: 'compiled' }];

    const out = await withActiveLedger(ledger, () =>
      runCoverageSweep(dir, candidates, [], async (content) => { read.push(content); return benign; }, true,
        undefined, () => undefined),
    );

    expect(ledger.unreadableInputs.count).toBe(0);
    expect(read).toEqual([]);
    expect(out.stats.swept).toBe(0);
  });

  it('a compiled candidate is classified from the off-ledger re-read, not a tracked read', async () => {
    const ledger = new CoverageLedger(dir);
    const read: string[] = [];
    const candidates: CoverageCandidate[] = [{ path: 'SKILL.md', artifactType: 'skill', provenance: 'compiled' }];

    await withActiveLedger(ledger, () =>
      runCoverageSweep(dir, candidates, [], async (content) => { read.push(content); return benign; }, true,
        undefined, (file) => (file === 'SKILL.md' ? 'bytes from the re-read' : undefined)),
    );

    expect(read).toEqual(['bytes from the re-read']);
    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it('a compiled candidate with no re-read available is skipped, never read tracked', async () => {
    const ledger = new CoverageLedger(dir);
    const candidates: CoverageCandidate[] = [{ path: 'SKILL.md', artifactType: 'skill', provenance: 'compiled' }];

    await withActiveLedger(ledger, () => runCoverageSweep(dir, candidates, [], async () => benign, true));

    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it('control: a sweep-only candidate keeps its tracked read, so the same loss IS recorded', async () => {
    const ledger = new CoverageLedger(dir);
    const candidates: CoverageCandidate[] = [{ path: 'SKILL.md', artifactType: 'document', provenance: 'sweep-only' }];

    await withActiveLedger(ledger, () =>
      runCoverageSweep(dir, candidates, [], async () => benign, true, undefined, () => 'must not be used'),
    );

    expect(ledger.unreadableInputs.count).toBe(1);
  });
});

describe('#520 the bridge states each candidate\'s provenance and hands over an off-ledger re-read', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'hma-520-bridge-'));
    await writeFile(join(dir, 'SKILL.md'), '---\nname: summariser\n---\n\nSummarise the file the user names.\n');
    await writeFile(join(dir, 'notes.txt'), 'Plain notes.\n');
  });

  afterEach(async () => {
    await chmod(join(dir, 'SKILL.md'), 0o644).catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  });

  it('compiled files are `compiled`, sweep-only documents are `sweep-only`', async () => {
    const result = await runNanoMindScan(dir, []);
    const byPath = new Map(result.coverageCandidates.map((c) => [c.path, c.provenance]));
    expect(byPath.get('SKILL.md')).toBe('compiled');
    expect(byPath.get('notes.txt')).toBe('sweep-only');
    expect(typeof result.rereadArtifact).toBe('function');
  });

  it.skipIf(!canMakeUnreadable)('its re-read of a now-unreadable compiled file records nothing', async () => {
    const result = await runNanoMindScan(dir, []);
    await chmod(join(dir, 'SKILL.md'), 0o000);
    const ledger = new CoverageLedger(dir);

    const bytes = await withActiveLedger(ledger, async () => result.rereadArtifact?.('SKILL.md'));

    expect(bytes).toBeUndefined();
    expect(ledger.unreadableInputs.count).toBe(0);
  });
});
