/**
 * Automated Training Data Pipeline
 *
 * Every HMA scan with --semantic or --simulate flags automatically
 * generates labeled training data for NanoMind. This closes the
 * improvement loop: scan -> observe -> label -> train -> improve.
 *
 * Training data is written to ~/.opena2a/training-data/ as JSONL files.
 * The NanoMind training pipeline reads from this directory during
 * SFT (supervised fine-tuning) stages.
 */

import { writeFileSync, mkdirSync, appendFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { AttackSessionResult } from './types.js';
import type { SimulationResult } from '../simulation/types.js';

const TRAINING_DIR = join(homedir(), '.opena2a', 'training-data');
const CORPUS_FILE = join(TRAINING_DIR, 'labeled-pairs.jsonl');
const MANIFEST_FILE = join(TRAINING_DIR, 'manifest.json');

export interface TrainingPair {
  /** The artifact content that was scanned/attacked */
  input: string;
  /** Ground truth label */
  label: 'malicious' | 'benign' | 'edge_case' | 'defense';
  /** Attack class (for malicious) or defense mechanism (for defense) */
  attackClass: string;
  /** Behavioral evidence from simulation or attack */
  evidence: string;
  /** Confidence in the label (0-1) */
  confidence: number;
  /** Source of this training pair */
  source: 'simulation' | 'attack_session' | 'scan';
  /** When this pair was generated */
  timestamp: string;
}

/**
 * Initialize the training data directory.
 */
export function initTrainingPipeline(): void {
  mkdirSync(TRAINING_DIR, { recursive: true });
  if (!existsSync(MANIFEST_FILE)) {
    writeFileSync(MANIFEST_FILE, JSON.stringify({
      version: '1.0',
      createdAt: new Date().toISOString(),
      totalPairs: 0,
      pairsByLabel: { malicious: 0, benign: 0, edge_case: 0, defense: 0 },
      pairsBySource: { simulation: 0, attack_session: 0, scan: 0 },
    }, null, 2));
  }
}

/**
 * Export simulation results as training data.
 * CLEAN simulations -> benign labels. MALICIOUS -> malicious labels.
 */
export function exportSimulationTraining(
  artifactContent: string,
  result: SimulationResult,
): number {
  initTrainingPipeline();
  let count = 0;

  if (result.verdict === 'CLEAN') {
    appendPair({
      input: artifactContent.slice(0, 4096),
      label: 'benign',
      attackClass: 'none',
      evidence: `All ${result.probeCount} probes passed. Semantic delta: ${result.semanticDelta.toFixed(2)}.`,
      confidence: result.confidence,
      source: 'simulation',
      timestamp: new Date().toISOString(),
    });
    count++;
  } else if (result.verdict === 'MALICIOUS') {
    for (const probe of result.failedProbes) {
      appendPair({
        input: artifactContent.slice(0, 4096),
        label: 'malicious',
        attackClass: probe.attackClass,
        evidence: probe.observedBehavior,
        confidence: probe.confidence,
        source: 'simulation',
        timestamp: new Date().toISOString(),
      });
      count++;
    }
  }

  return count;
}

/**
 * Export attack session results as training data.
 * Successful attacks -> malicious behavior. Failed attacks -> defense patterns.
 *
 * Writes NOTHING for a session that executed no payloads (#369). `input` here is
 * the target's observed response; without a run there is none, and the templated
 * stand-in this used to write is what put 1,001 synthetic self-labeled rows into
 * the corpus before the 2026-06-01 audit. The corpus file is only opened when
 * there is a real observation to append.
 */
export function exportAttackTraining(session: AttackSessionResult): number {
  if (session.evaluation.mode !== 'executed') return 0;

  initTrainingPipeline();
  let count = 0;

  for (const result of session.results) {
    // No observation, no row.
    if (!result.observedBehavior) continue;

    if (result.outcome === 'SUCCESS') {
      appendPair({
        input: result.observedBehavior,
        label: 'malicious',
        attackClass: result.category,
        evidence: `Attack succeeded: ${result.payloadId}`,
        confidence: result.confidence,
        source: 'attack_session',
        timestamp: new Date().toISOString(),
      });
      count++;
    } else if (result.outcome === 'FAIL' && result.defenseMechanism) {
      appendPair({
        input: result.observedBehavior,
        label: 'defense',
        attackClass: result.category,
        evidence: `Defense held: ${result.defenseMechanism}`,
        confidence: result.confidence,
        source: 'attack_session',
        timestamp: new Date().toISOString(),
      });
      count++;
    }
  }

  return count;
}

/**
 * Export a single scan result as training data.
 * Used by the --semantic flag when NanoMind classifies a finding.
 */
export function exportScanTraining(
  artifactContent: string,
  label: 'malicious' | 'benign',
  attackClass: string,
  confidence: number,
): void {
  initTrainingPipeline();

  appendPair({
    input: artifactContent.slice(0, 4096),
    label,
    attackClass,
    evidence: `NanoMind semantic classification`,
    confidence,
    source: 'scan',
    timestamp: new Date().toISOString(),
  });
}

/**
 * Append a training pair to the JSONL corpus file.
 */
function appendPair(pair: TrainingPair): void {
  appendFileSync(CORPUS_FILE, JSON.stringify(pair) + '\n');
}

/**
 * Get training data statistics.
 */
export function getTrainingStats(): {
  totalPairs: number;
  corpusPath: string;
  exists: boolean;
} {
  // Count lines (each line = one training pair)
  try {
    const { readFileSync } = require('node:fs');
    const content = readFileSync(CORPUS_FILE, 'utf-8');
    const lines = content.split('\n').filter((l: string) => l.trim().length > 0);
    return { totalPairs: lines.length, corpusPath: CORPUS_FILE, exists: true };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    // ENOENT = corpus doesn't exist yet (normal on first run).
    // Other errors (EACCES on ~/.opena2a) surface so the caller knows
    // stats can't be computed, instead of reporting 0 pairs.
    if (code && code !== 'ENOENT') throw e;
    return { totalPairs: 0, corpusPath: CORPUS_FILE, exists: false };
  }
}
