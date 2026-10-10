/**
 * `--nanomind` with the analyst installed and its daemon stopped says so, and
 * names `nanomind-analyst start`.
 *
 * The daemon stops by itself when idle, so "installed, not running" is the
 * ordinary state of a finished install. The scan used to report it with the
 * line written for a machine that has no analyst at all:
 *
 *   NanoMind generative model not set up. Run: hackmyagent nanomind setup
 *
 * which is false for a finished install and names the wrong command: setup
 * runs the install again. The cells below hold the daemon unreachable and vary
 * only whether an install is found.
 *
 * RED-ON-BASE cells fail on the build before the fix; PIN cells pass on both.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';

const analyst = vi.hoisted(() => ({ installedStopped: false }));

// The orchestrator's heavy dependencies are replaced so the cells exercise
// only what it reports when the analyst is not ready.
vi.mock('../../src/nanomind-core/daemon-lifecycle', () => ({ ensureDaemon: async () => false }));
vi.mock('../../src/nanomind-core/inference/tme-classifier', () => ({
  getTMEClassifier: () => ({ ensureModel: async () => undefined }),
}));
vi.mock('../../src/nanomind-core/inference/security-analyst', () => ({
  isAnalystReady: async () => false,
  isAnalystInstalledStopped: async () => analyst.installedStopped,
  runAnalystInference: async () => null,
  classifyArtifactForCoverage: async () => null,
}));
vi.mock('../../src/nanomind-core/scanner-bridge', () => ({
  runNanoMindScan: async () => ({
    mergedFindings: [],
    astFindings: [],
    nanomindAvailable: true,
    compiledArtifacts: 1,
    compileSetTruncated: false,
    semanticFamilyCoverage: { totalFamilies: 0, artifactsCompiled: 1, fullyExamined: 1, partial: [] },
    artifactSummaries: [],
    integrityStatus: 'CLEAN',
    coverageCandidates: [],
  }),
}));

import { orchestrateNanoMind } from '../../src/nanomind-core/orchestrate';

/** Run the orchestrator with `--nanomind` and return what it wrote to stderr. */
async function scan(silent: boolean) {
  const written: string[] = [];
  const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    written.push(String(chunk));
    return true;
  });
  try {
    const result = await orchestrateNanoMind('/nonexistent-analyst-stopped', [], {
      nanomind: true,
      silent,
      deferTelemetryFlush: true,
    });
    return { result, stderr: written.join('') };
  } finally {
    spy.mockRestore();
  }
}

afterEach(() => {
  analyst.installedStopped = false;
});

describe('--nanomind with the analyst installed and its daemon stopped', () => {
  it('RED-ON-BASE: says installed and stopped, names `nanomind-analyst start`, and does not say "not set up"', async () => {
    analyst.installedStopped = true;
    const { result, stderr } = await scan(false);

    expect(stderr).toContain('NanoMind analyst is installed and its daemon is stopped.');
    expect(stderr).toContain('Start it: nanomind-analyst start');
    expect(stderr).not.toMatch(/not set up/i);
    expect(stderr).not.toContain('nanomind setup');
    expect(result.analystZeroState).toEqual({
      reason: 'installed-stopped',
      modelLabel: 'Qwen3 v3.0.0 inline',
    });
  });

  it('RED-ON-BASE: records the state for the renderer when the run is silent, and prints nothing', async () => {
    analyst.installedStopped = true;
    const { result, stderr } = await scan(true);

    expect(stderr).toBe('');
    expect(result.analystZeroState?.reason).toBe('installed-stopped');
  });

  it('PIN: the analyst produced nothing either way, so no analyst findings or escalations are reported', async () => {
    analyst.installedStopped = true;
    const { result } = await scan(true);

    expect(result.analystFindings).toBeUndefined();
    expect(result.analystEscalations).toBeUndefined();
    expect(result.coverageSweep).toBeUndefined();
  });
});

describe('--nanomind with no analyst installed', () => {
  it('PIN: still points at setup', async () => {
    const { result, stderr } = await scan(false);

    expect(stderr).toContain('NanoMind generative model not set up. Run: hackmyagent nanomind setup');
    expect(stderr).not.toContain('nanomind-analyst start');
    expect(result.analystZeroState).toEqual({
      reason: 'not-ready',
      modelLabel: 'Qwen3 v3.0.0 inline',
    });
  });
});
