/**
 * The `secure --deep` behavioural simulation run.
 *
 * The run used to live inline in the CLI behind a text-format guard, so
 * `secure --deep --json` (and sarif, html, asff) skipped it and said nothing:
 * the flag meant one thing in the terminal and another in CI. It lives here so
 * every output format takes the same path, and so the result is a value the
 * JSON document can carry, not only lines on stderr.
 *
 * The result is advisory. It never moves the score, the findings or the exit
 * code, so the report carries counts and probe ids and no severity word.
 *
 * This module reads no file: the caller walks the tree and hands over a
 * reader, which keeps the out-of-tree link confinement at the walk. The engine
 * is loaded on first use, so importing this module costs a command that never
 * passes `--deep` nothing.
 */
import path from 'node:path';
import { escapeForDisplay, escapePathForDisplay } from '../ui/display-safe';
import type { SimulationEngine } from './engine.js';
import type { SimulationResult } from './types.js';

/** A run simulates at most this many artifacts; the rest are counted, not probed. */
export const DEEP_SIMULATION_ARTIFACT_LIMIT = 10;

const NO_EXECUTOR = 'no probe executor (NanoMind daemon, Ollama, or ANTHROPIC_API_KEY)';

/**
 * - `measured`: an executor ran the probes against every simulated artifact.
 *   An artifact sent no probe is listed in `notSimulated`, never here.
 * - `not-measured`: no probe was sent, because no executor was available or
 *   every artifact is over the redaction size limit; `reason` names each
 *   cause that holds.
 * - `no-artifacts`: the tree holds nothing to simulate.
 * - `error`: the run stopped early; `reason` says why.
 */
export type DeepSimulationStatus = 'measured' | 'not-measured' | 'no-artifacts' | 'error';

export interface DeepSimulationArtifact {
  /** Path relative to the scan target, `/`-separated. */
  file: string;
  probeCount: number;
  flaggedCount: number;
  /** Ids of the probes whose response was flagged. */
  flaggedProbes: string[];
}

/** An artifact in the simulated batch that was sent no probe, and why. */
export interface DeepSimulationSkippedArtifact {
  /** Path relative to the scan target, `/`-separated. */
  file: string;
  reason: string;
}

/** The `simulation` block of `secure --deep --json`. */
export interface DeepSimulationReport {
  /** Always true: the simulation never moves the score, the findings or the exit code. */
  advisory: true;
  status: DeepSimulationStatus;
  /** Backend that executed the probes; null when none ran. */
  executor: string | null;
  artifactsFound: number;
  /** Lower than `artifactsFound` when the limit was reached or the run stopped early. */
  artifactsSimulated: number;
  artifactLimit: number;
  /** Links resolving outside the scanned tree, which the walk does not follow. */
  linksSkipped: number;
  artifacts: DeepSimulationArtifact[];
  /**
   * Present when an artifact was sent no probe: one over the redaction size
   * limit. Not in `artifacts` and not counted in `artifactsSimulated`.
   */
  notSimulated?: DeepSimulationSkippedArtifact[];
  /** Present on `not-measured` and `error`: why no (further) probe ran. */
  reason?: string;
}

export interface DeepSimulationInput {
  /** The scan target; artifact paths are reported relative to it. */
  targetDir: string;
  /** Absolute paths of the artifacts found, in walk order. */
  files: string[];
  linksSkipped: number;
  /** Reads one artifact. The caller owns the read, and with it the confinement. */
  read: (file: string) => string;
  /** Where the progress lines go: stderr in the CLI, beside whatever stdout carries. */
  write: (text: string) => void;
  /** Probe runner. Defaults to an engine that detects its own executor; tests inject one. */
  engine?: Pick<SimulationEngine, 'runLayer3' | 'resolveExecutor'>;
  /** Called once per measured artifact. */
  onMeasured?: (content: string, result: SimulationResult) => void | Promise<void>;
}

function emptyReport(artifactsFound: number, linksSkipped: number): DeepSimulationReport {
  return {
    advisory: true,
    status: 'no-artifacts',
    executor: null,
    artifactsFound,
    artifactsSimulated: 0,
    artifactLimit: DEEP_SIMULATION_ARTIFACT_LIMIT,
    linksSkipped,
    artifacts: [],
  };
}

/** The report for a run that failed before any artifact was reached. */
export function deepSimulationFailure(reason: string): DeepSimulationReport {
  return { ...emptyReport(0, 0), status: 'error', reason };
}

/**
 * Run the full probe battery against each artifact, up to the limit, writing
 * one progress line per step and returning what was observed.
 *
 * Never throws: a read, load or executor failure ends the run with
 * `status: 'error'` and whatever was measured before it.
 */
export async function runDeepSimulation(input: DeepSimulationInput): Promise<DeepSimulationReport> {
  const { files, linksSkipped, write } = input;
  const report = emptyReport(files.length, linksSkipped);

  if (linksSkipped > 0) {
    write(`\n[Simulation] ${linksSkipped} link${linksSkipped === 1 ? '' : 's'} resolving outside the scanned tree skipped.\n`);
  }
  if (files.length === 0) {
    write(`\n[Simulation] No skill/SOUL/MCP artifacts found. Simulation skipped.\n\n`);
    return report;
  }

  const batch = files.slice(0, DEEP_SIMULATION_ARTIFACT_LIMIT);
  const scope = batch.length < files.length
    ? `${batch.length} of ${files.length} artifact(s) (limit ${DEEP_SIMULATION_ARTIFACT_LIMIT}; the rest are not simulated)`
    : `${files.length} artifact(s)`;
  write(`\n[Simulation] Running behavioral simulation on ${scope}...\n`);

  try {
    // The engine resolves its own executor (NanoMind daemon, Ollama,
    // ANTHROPIC_API_KEY). Without one it runs no probe and reports
    // NOT_MEASURED; the static findings are then the whole verdict. A verdict
    // computed from the artifact's own wording rated the SOUL.md that
    // `harden-soul` writes MALICIOUS (#446).
    const { SimulationEngine, parseSkillProfile } = await import('./engine.js');
    const { MAX_REDACTION_INPUT_BYTES } = await import('../nanomind-core/security/defense-in-depth.js');
    const engine = input.engine ?? new SimulationEngine({ useLLM: true });
    const overLimit = `over the ${MAX_REDACTION_INPUT_BYTES}-byte limit the credential redaction reads, so no probe was sent`;

    for (const file of batch) {
      const name = path.basename(file);
      // The progress lines name the file as `--json` does: two `SKILL.md`
      // files in different directories read the same by basename (#1024).
      const relative = path.relative(input.targetDir, file).split(path.sep).join('/');
      const content = input.read(file);

      // The prompt carries the file only through the credential redaction,
      // which withholds content over its size limit whole. Probing that would
      // run every probe against the withheld marker and report a clean
      // measurement of a file no executor saw, so the file is sent no probe
      // and listed as not simulated.
      if (Buffer.byteLength(content, 'utf-8') > MAX_REDACTION_INPUT_BYTES) {
        write(`  [Simulation] ${escapePathForDisplay(relative)} — NOT SIMULATED: ${overLimit}; the Findings block is the verdict.\n`);
        (report.notSimulated ??= []).push({
          file: relative,
          reason: overLimit,
        });
        continue;
      }

      const result = await engine.runLayer3(parseSkillProfile(content, name));

      if (!result.measured) {
        write(`  [Simulation] NOT MEASURED — ${NO_EXECUTOR}; the Findings block is the verdict.\n`);
        report.status = 'not-measured';
        report.reason = NO_EXECUTOR;
        break;
      }

      // Advisory only: the line carries a count and the probe ids, not a
      // severity word.
      const flaggedProbes = result.failedProbes.map((p) => p.probeId);
      write(`  [INFO] ${escapePathForDisplay(relative)} — ${flaggedProbes.length}/${result.probeCount} probes flagged (advisory, not scored)${flaggedProbes.length > 0 ? `: ${flaggedProbes.join(', ')}` : ''}\n`);

      report.status = 'measured';
      report.executor = result.executor;
      report.artifacts.push({
        file: relative,
        probeCount: result.probeCount,
        flaggedCount: flaggedProbes.length,
        flaggedProbes,
      });
      report.artifactsSimulated = report.artifacts.length;

      await input.onMeasured?.(content, result);
    }
    if (report.status === 'no-artifacts' && report.notSimulated) {
      // Every artifact reached was over the limit: nothing was measured. No
      // probe ran, so whether an executor exists is still unknown; without
      // one, a file brought within the limit would not be simulated either,
      // and the reason says so.
      report.status = 'not-measured';
      report.reason = `every artifact reached is ${overLimit}`;
      if ((await engine.resolveExecutor()) === null) {
        write(`  [Simulation] NOT MEASURED — ${NO_EXECUTOR}; the Findings block is the verdict.\n`);
        report.reason += `, and there is ${NO_EXECUTOR} to probe a file within the limit`;
      }
    }
    write(`[Simulation] Complete.\n\n`);
  } catch (err) {
    const reason = err instanceof Error ? err.message : 'unknown error';
    write(`[Simulation] Skipped: ${escapeForDisplay(reason)}\n\n`);
    report.status = 'error';
    report.reason = reason;
  }
  return report;
}
