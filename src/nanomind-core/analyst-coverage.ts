/**
 * Analyst coverage routing (NanoMind Phase A — P1, CDS-023).
 *
 * The v3.0.0 reasoning analyst (`sendClassify` -> gate -> Qwen3-1.7B NLM) can
 * recover behavioral attacks the structural AST pipeline misses. But its raw
 * verdict is NOT safe to auto-apply (CDS-024): on dual-use security code it
 * carries ~22% false-positive rate and its confidences cluster near 0.95 (weak
 * calibration, measured 2026-06-05). This module is the routing layer that lets
 * the analyst INFORM and ESCALATE without auto-flipping the deterministic
 * verdict, until a policy is chosen in P3.
 *
 * It is intentionally PURE and dependency-free: it post-processes one analyst
 * verdict + the structural signal and returns a routed decision. The same
 * function backs both the live daemon path (a `ClassifyOkResponse` is
 * structurally an `AnalystVerdict`) and the offline benchmark JOIN that
 * measures F1/FPR over captured verdicts.
 *
 * This module is measurement-path only in P1. It is deliberately NOT wired into
 * `orchestrateNanoMind` / `scanner-bridge` — shipped `secure` behavior is
 * unchanged. Wiring an auto-verdict into the product is gated behind P3
 * (the per-sample structural+analyst policy comparison vs the published
 * 82.9% F1 / 1.16% FPR).
 */

/** Routed analyst contribution to a per-artifact verdict. */
export type RoutedAnalystVerdict =
  | 'attack' // names a real attack class at HIGH/CRITICAL — high-confidence threat
  | 'benign' // gate-suppressed, or none/benign — no threat
  | 'abstain'; // uncertain (mid-severity attack class or "suspicious") — escalate, do not auto-verdict

/** Policy for combining the structural verdict with the routed analyst verdict. */
export type CombinePolicy =
  | 'structural-only' // baseline: analyst ignored
  | 'union' // analyst auto-adds attacks (max recall; pays the analyst's benign FPR)
  | 'abstention-gated'; // structural auto-verdict stands; analyst only ESCALATES misses (CDS-024 safe)

/**
 * The subset of the daemon's classify response this layer reasons about.
 * `ClassifyOkResponse` from nanomind-guard-client is assignable to this, as is a
 * captured-verdict record from the offline measurement harness.
 */
export interface AnalystVerdict {
  /** "none" | "benign" | <attack class>; constant "none" on the gate-bypass path. */
  attackClass: string;
  /** "benign" | "suspicious" | "malicious"; optional (not all captures carry it). */
  classification?: string;
  /** "critical" | "high" | "medium" | "low" | "none" | null. */
  severity: string | null;
  /** null on the gate-bypass path, a number on the NLM path. */
  confidence?: number | null;
  /** "input-classifier-gate" (suppressed) or "nlm" (model ran). */
  source?: 'input-classifier-gate' | 'nlm' | string;
}

export interface CombinedVerdict {
  /** Auto-applied verdict under the policy. `abstention-gated` never lets the analyst raise this. */
  attack: boolean;
  /**
   * The analyst surfaced something for human review that the auto-verdict did
   * not act on (a structural miss the analyst flagged, or an abstention). Drives
   * the escalation queue; never silently changes the score.
   */
  escalate: boolean;
}

/** Attack-class strings that mean "no attack". */
export const NON_ATTACK_CLASSES: ReadonlySet<string> = new Set(['none', 'benign', '']);
/** Severities that make a named attack class a confident threat. */
export const HIGH_SEVERITIES: ReadonlySet<string> = new Set(['critical', 'high']);
/** Severities that put a named attack class in the abstention band. */
export const MID_SEVERITIES: ReadonlySet<string> = new Set(['medium', 'low']);

/**
 * Canonical attack-class vocabulary: the TME 10-class taxonomy unioned with the
 * snake_case classes the v3.0.0 analyst actually emits (observed across the
 * DVAA + corpus captures). An auto-`attack` requires membership here.
 *
 * Robustness guard (P1 adversarial review M1): the analyst sometimes emits
 * free-form prose as its class ("Privilege Escalation / Unauthorized Command
 * Execution"), parser noise ("confidence: 0.15", "N/A"), or a hedge ("[No valid
 * attack class applies]"). Treating any non-benign string as a named attack
 * would let one hallucinated severity convert model word-salad into an
 * auto-verdict. Unknown classes therefore route to `abstain` (escalate for human
 * review) — the signal is preserved, but it never auto-flips the verdict.
 */
export const KNOWN_ATTACK_CLASSES: ReadonlySet<string> = new Set([
  // TME 10-class taxonomy
  'prompt_injection', 'data_exfiltration', 'tool_abuse', 'privilege_escalation',
  'model_manipulation', 'social_engineering', 'supply_chain', 'denial_of_service',
  'steganographic_attack',
  // Analyst-emitted classes observed in captures
  'injection', 'exfiltration', 'lateral_movement', 'persistence', 'credential_abuse',
  'steganography', 'policy_violation', 'heartbeat_rce', 'credential_exfiltration',
  'unicode_stego', 'parser_differential', 'prompt_injection_vulnerability', 'jailbreak',
]);

function norm(s: string | null | undefined): string {
  return (s ?? '').trim().toLowerCase();
}

/** True iff the analyst named a real (non-benign) attack class — including prose. */
export function namesAttackClass(v: AnalystVerdict): boolean {
  return !NON_ATTACK_CLASSES.has(norm(v.attackClass));
}

/** True iff the class is a recognised canonical attack class (auto-`attack` gate). */
export function isKnownAttackClass(v: AnalystVerdict): boolean {
  return KNOWN_ATTACK_CLASSES.has(norm(v.attackClass));
}

/**
 * Route one analyst verdict into attack / benign / abstain.
 *
 * Posture-vs-attack: an analyst output is an `attack` ONLY when it names a real
 * attack class at HIGH/CRITICAL severity — matching the structural verdict's
 * own "high/critical attack finding" bar so the two halves are comparable. A
 * gate-suppressed verdict (`source: input-classifier-gate`, attackClass "none")
 * is `benign` by construction.
 *
 * Calibrated abstention is severity/agreement-based, NOT confidence-based: the
 * v3.0.0 analyst's confidences cluster near 0.95 regardless of correctness
 * (selective-risk is non-monotonic — baseline 2026-06-05), so thresholding on
 * `confidence` would be measurement theatre. Instead, a real attack class at
 * MEDIUM/LOW severity, or a "suspicious" classification, is treated as `abstain`
 * (uncertain — escalate for human review) rather than a confident verdict.
 */
export function routeAnalystVerdict(v: AnalystVerdict): RoutedAnalystVerdict {
  // Gate-suppressed path is benign by construction (no model judgement made).
  if (norm(v.source) === 'input-classifier-gate') return 'benign';

  const classification = norm(v.classification);
  if (!namesAttackClass(v)) {
    // No attack class. "suspicious" with no class still warrants a look.
    return classification === 'suspicious' ? 'abstain' : 'benign';
  }

  // Non-benign but unrecognised class (free-form prose / parser noise / hedge):
  // never auto-`attack`; escalate for human review instead (robustness guard).
  if (!isKnownAttackClass(v)) return 'abstain';

  const sev = norm(v.severity);
  if (HIGH_SEVERITIES.has(sev)) return 'attack';
  if (MID_SEVERITIES.has(sev)) return 'abstain';

  // Known attack class with no/unknown severity: uncertain, not confident.
  return 'abstain';
}

/**
 * Combine the structural verdict (HIGH/CRITICAL attack finding present, posture
 * excluded) with the routed analyst verdict under a policy.
 *
 *  - `structural-only`  analyst ignored; the published baseline.
 *  - `union`            analyst auto-adds attacks. Maximises recall but inherits
 *                       the analyst's benign FPR — NOT auto-safe (CDS-024); for
 *                       measuring the recall ceiling and the FPR cost only.
 *  - `abstention-gated` the structural auto-verdict is never raised by the
 *                       analyst; an analyst `attack`/`abstain` on a structural
 *                       miss becomes an ESCALATION (human review). Auto-FPR
 *                       therefore equals the structural FPR. This is the only
 *                       policy that is safe to run in product before P3.
 */
export function combineVerdict(
  structuralAttack: boolean,
  analyst: RoutedAnalystVerdict,
  policy: CombinePolicy,
): CombinedVerdict {
  switch (policy) {
    case 'structural-only':
      return { attack: structuralAttack, escalate: false };

    case 'union':
      return {
        attack: structuralAttack || analyst === 'attack',
        // Mid-band analyst signal on an otherwise-clean artifact still escalates.
        escalate: !structuralAttack && analyst === 'abstain',
      };

    case 'abstention-gated':
      return {
        // Analyst NEVER raises the auto-verdict pre-P3.
        attack: structuralAttack,
        // It surfaces structural misses (attack or abstain) for human review.
        escalate: !structuralAttack && (analyst === 'attack' || analyst === 'abstain'),
      };
  }
}
