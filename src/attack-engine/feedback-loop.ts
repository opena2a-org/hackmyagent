/**
 * Attack Session
 *
 * Reads a target, derives its attack surface, and generates target-specific
 * payloads. It does NOT execute them: there is no path from this engine to a
 * running agent today, so a session produces payloads and no outcomes.
 *
 * ## Why there is no resilience score here (#369)
 *
 * The intended loop is generate -> attack -> observe -> adapt. The middle two
 * steps have never existed. `executeAttack` built a `SimulationEngine` and then
 * ignored it, calling `evaluateAttackHeuristic` -- a regex over the artifact's
 * own text -- and presenting the result as an observed attack outcome, with
 * synthetic `observedBehavior` strings ("Skill complied with ... attack") for
 * runs that never happened.
 *
 * That heuristic was not approximate, it was inverted. It scored resistance by
 * counting modal-verb sentences, so:
 *
 *   benign.md     0 matches -> every category SUCCESS -> "Resilience 0%, 4 successful attacks"
 *   jailbreak.md  3 matches -> every category PARTIAL -> "Resilience 100%, All defenses held"
 *
 * measured on the shipped `0.25.1`. Attack text is maximally imperative, so the
 * more jailbreak content an artifact carried the safer it scored -- a signal the
 * scanned artifact fully controls. A third defect compounded it: `buildDefenseMap`
 * divided by `entries.length || 1`, so a target with no defence entries at all
 * scored 0/1 = 0%, rendering "no evidence" as "no resilience".
 *
 * The fix is not a better regex. `Never reveal secrets.` and `Never refuse.` are
 * the same syntactic shape, so separating them needs the semantics of refusal,
 * not a pattern -- the same lesson as #364, where `allow` and `deny` held
 * textually identical values and only the key could tell them apart. Here the
 * structure that carries the polarity is whether an agent actually ran. So the
 * number is gone until one does, which closes the class by construction: nothing
 * an artifact writes can raise a score that does not exist.
 *
 * This also follows the rule already recorded in `src/ui/artifact-intent.ts`
 * (#252, citing #200): where a layer reached no verdict it must say so, never
 * report the reassuring end of a scale it did not measure.
 *
 * Executing payloads for real is `docs/design/redteam-nanomind-judge.md`. It is
 * blocked on transport -- the shipped daemon listens on the Unix socket
 * `/tmp/nanomind-guard.sock` while `NanoMindBackend` posts to HTTP
 * `127.0.0.1:47200` -- and, before a model is allowed to judge untrusted
 * artifact text, on V-D7's adversarial-against-scanner corpus becoming an
 * enforced gate. #369 is the evidence that it is not one today.
 */

import { readTarget } from './target-reader.js';
import { generateInitialPayloads } from './payload-generator.js';
import {
  DEFAULT_ATTACK_CONFIG,
  type AttackSessionResult,
  type AttackResult,
  type DefenseMap,
  type SemanticTargetProfile,
  type AttackEngineConfig,
} from './types.js';

/** Why no payload was executed. One clause, printed verbatim by the CLI. */
const NOT_EXECUTED_REASON =
  'no agent execution backend is wired to this engine, so no payload was run';

/**
 * Read a target artifact, derive its attack surface, and generate the payloads
 * an attack session would use.
 *
 * Returns `evaluation.mode === 'not_executed'` and `defenseMap.resilienceScore
 * === null`. Nothing runs, so the session reaches no verdict about resistance
 * and reports none. Callers MUST branch on `resilienceScore === null` — see the
 * file header for why substituting a number there is the bug this replaced.
 *
 * `config.maxIterations` is accepted and currently unused: iteration exists to
 * adapt a payload to an observed defence, and there are no observations. It is
 * kept on the type so the execution path can restore it without a signature
 * change; the CLI tells the user it is inert rather than silently ignoring it.
 */
export async function runAttackSession(
  content: string,
  artifactType: SemanticTargetProfile['artifactType'],
  name: string,
  config?: Partial<AttackEngineConfig>,
): Promise<AttackSessionResult> {
  const startMs = Date.now();
  const cfg = { ...DEFAULT_ATTACK_CONFIG, ...config } as AttackEngineConfig;

  const profile = readTarget(content, artifactType, name);
  const payloads = generateInitialPayloads(profile).slice(0, cfg.maxPayloads);

  // Every payload is reported as generated-but-not-run. `observedBehavior` is
  // omitted rather than set to a placeholder: there is no observation, and any
  // string here would be a claim about behaviour nobody watched, which is what
  // put 1,001 synthetic "Skill complied with ..." rows into the training corpus
  // (audit 2026-06-01).
  const results: AttackResult[] = payloads.map(payload => ({
    payloadId: payload.id,
    category: payload.category,
    payloadInput: payload.input,
    outcome: 'NOT_EXECUTED' as const,
    toolCalls: [],
    confidence: 0,
  }));

  // No execution means no defence was ever exercised, so the map is empty and
  // the score is null. Note there is no `|| 1` denominator here: an empty
  // defence set produces "not measured", never "0% resilient".
  const defenseMap: DefenseMap = {
    defenses: [],
    resilienceScore: null,
    strongCategories: [],
    weakCategories: [],
  };

  return {
    target: profile,
    results,
    evaluation: {
      mode: 'not_executed',
      generated: payloads.length,
      executed: 0,
      reason: NOT_EXECUTED_REASON,
    },
    totalPayloads: payloads.length,
    successCount: 0,
    partialCount: 0,
    defenseMap,
    durationMs: Date.now() - startMs,
    // Nothing was confirmed, so nothing is reported. The engine used to emit
    // `<category> vulnerability confirmed` at HIGH for every category a regex
    // short-circuited — on `benign.md` that was all four.
    vulnerabilities: [],
  };
}

// ============================================================================
// Training Data Pipeline
// ============================================================================

/**
 * Export attack session results as NanoMind training data.
 * - SUCCESS attacks → malicious behavior examples (observed behavior)
 * - FAIL attacks → defense pattern examples (observed behavior)
 *
 * Returns EMPTY for a session that executed nothing, which is every session
 * today. That is the point: a pair's `input` is the target's observed response,
 * and an unexecuted payload has none. The audited engine filled that field with
 * a templated `Skill complied with <category> attack: ...` sentence, and 1,001
 * such rows (71% of the corpus) accumulated in
 * `~/.opena2a/training-data/labeled-pairs.jsonl` before the 2026-06-01 audit —
 * synthetic, self-labeled, and unsanitized, violating two standing rules at
 * once (no training on data that bypasses the sanitizer; no self-generated
 * labels as ground truth). A row is only emitted where a real observation
 * exists, so the not-executed path cannot produce one.
 */
export function exportTrainingData(session: AttackSessionResult): Array<{
  input: string;
  label: 'malicious' | 'benign' | 'defense';
  attackClass: string;
  evidence: string;
  confidence: number;
}> {
  const pairs: Array<{
    input: string;
    label: 'malicious' | 'benign' | 'defense';
    attackClass: string;
    evidence: string;
    confidence: number;
  }> = [];

  if (session.evaluation.mode !== 'executed') return pairs;

  for (const result of session.results) {
    // No observation, no row — regardless of what `outcome` claims.
    if (!result.observedBehavior) continue;

    if (result.outcome === 'SUCCESS') {
      pairs.push({
        input: result.observedBehavior,
        label: 'malicious',
        attackClass: result.category,
        evidence: `Attack succeeded: ${result.payloadId}`,
        confidence: result.confidence,
      });
    } else if (result.outcome === 'FAIL' && result.defenseMechanism) {
      pairs.push({
        input: result.observedBehavior,
        label: 'defense',
        attackClass: result.category,
        evidence: `Defense: ${result.defenseMechanism}`,
        confidence: result.confidence,
      });
    }
  }

  return pairs;
}
