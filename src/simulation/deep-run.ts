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
 * - `not-measured`: no executor was available, so no probe was sent.
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
  engine?: Pick<SimulationEngine, 'runLayer3'>;
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
    const engine = input.engine ?? new SimulationEngine({ useLLM: true });

    for (const file of batch) {
      const name = path.basename(file);
      const content = input.read(file);
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
      write(`  [INFO] ${escapePathForDisplay(name)} — ${flaggedProbes.length}/${result.probeCount} probes flagged (advisory, not scored)${flaggedProbes.length > 0 ? `: ${flaggedProbes.join(', ')}` : ''}\n`);

      report.status = 'measured';
      report.executor = result.executor;
      report.artifacts.push({
        file: path.relative(input.targetDir, file).split(path.sep).join('/'),
        probeCount: result.probeCount,
        flaggedCount: flaggedProbes.length,
        flaggedProbes,
      });
      report.artifactsSimulated = report.artifacts.length;

      await input.onMeasured?.(content, result);
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
