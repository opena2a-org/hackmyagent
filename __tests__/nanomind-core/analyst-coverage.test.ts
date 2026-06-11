import { describe, it, expect } from 'vitest';
import {
  routeAnalystVerdict,
  combineVerdict,
  namesAttackClass,
  isKnownAttackClass,
  NON_ATTACK_CLASSES,
  HIGH_SEVERITIES,
  KNOWN_ATTACK_CLASSES,
  type AnalystVerdict,
} from '../../src/nanomind-core/analyst-coverage';

// ============================================================================
// routeAnalystVerdict — posture-vs-attack + severity/agreement abstention
// ============================================================================

describe('routeAnalystVerdict', () => {
  const v = (over: Partial<AnalystVerdict>): AnalystVerdict => ({
    attackClass: 'none',
    severity: null,
    source: 'nlm',
    ...over,
  });

  it('gate-suppressed verdict is benign by construction (no model judgement)', () => {
    // Even if a stale attackClass/severity rides along, the gate path is benign.
    expect(
      routeAnalystVerdict(v({ source: 'input-classifier-gate', attackClass: 'privilege_escalation', severity: 'critical' })),
    ).toBe('benign');
  });

  it('real attack class at HIGH/CRITICAL is an attack', () => {
    expect(routeAnalystVerdict(v({ attackClass: 'privilege_escalation', severity: 'critical' }))).toBe('attack');
    expect(routeAnalystVerdict(v({ attackClass: 'credential_exfiltration', severity: 'high' }))).toBe('attack');
  });

  it('none/benign attack class is benign', () => {
    expect(routeAnalystVerdict(v({ attackClass: 'none', severity: 'none' }))).toBe('benign');
    expect(routeAnalystVerdict(v({ attackClass: 'benign', severity: null }))).toBe('benign');
    expect(routeAnalystVerdict(v({ attackClass: '', severity: null }))).toBe('benign');
  });

  it('real attack class at MEDIUM/LOW is the abstention band (escalate, not confident)', () => {
    expect(routeAnalystVerdict(v({ attackClass: 'data_exfiltration', severity: 'medium' }))).toBe('abstain');
    expect(routeAnalystVerdict(v({ attackClass: 'supply_chain', severity: 'low' }))).toBe('abstain');
  });

  it('real attack class with missing/unknown severity abstains (uncertain, not confident)', () => {
    expect(routeAnalystVerdict(v({ attackClass: 'persistence', severity: null }))).toBe('abstain');
    expect(routeAnalystVerdict(v({ attackClass: 'persistence', severity: 'weird' }))).toBe('abstain');
  });

  it('"suspicious" classification with no attack class abstains', () => {
    expect(routeAnalystVerdict(v({ attackClass: 'none', classification: 'suspicious' }))).toBe('abstain');
  });

  it('does NOT threshold on confidence (clustered ~0.95, unreliable) — high confidence does not upgrade severity', () => {
    // A mid-severity attack with very high confidence still abstains; confidence is ignored on purpose.
    expect(routeAnalystVerdict(v({ attackClass: 'data_exfiltration', severity: 'medium', confidence: 0.99 }))).toBe('abstain');
    // A high-severity attack with low confidence is still an attack (severity governs, not confidence).
    expect(routeAnalystVerdict(v({ attackClass: 'data_exfiltration', severity: 'high', confidence: 0.4 }))).toBe('attack');
  });

  it('robustness guard: non-benign UNKNOWN class (prose/parser-noise) never auto-attacks, even at HIGH/CRITICAL', () => {
    // Free-form prose the analyst sometimes emits as its class.
    expect(routeAnalystVerdict(v({ attackClass: 'Privilege Escalation / Unauthorized Command Execution', severity: 'critical' }))).toBe('abstain');
    // Parser noise / hedges.
    expect(routeAnalystVerdict(v({ attackClass: 'confidence: 0.15', severity: 'high' }))).toBe('abstain');
    expect(routeAnalystVerdict(v({ attackClass: '[No valid attack class applies]', severity: 'high' }))).toBe('abstain');
    expect(routeAnalystVerdict(v({ attackClass: 'N/A', severity: 'critical' }))).toBe('abstain');
  });

  it('known canonical classes DO auto-attack at HIGH/CRITICAL', () => {
    for (const cls of ['injection', 'exfiltration', 'lateral_movement', 'credential_abuse', 'heartbeat_rce']) {
      expect(routeAnalystVerdict(v({ attackClass: cls, severity: 'high' }))).toBe('attack');
    }
  });

  it('normalises case/whitespace on class and severity', () => {
    expect(routeAnalystVerdict(v({ attackClass: '  Privilege_Escalation ', severity: ' CRITICAL ' }))).toBe('attack');
    expect(routeAnalystVerdict(v({ attackClass: 'NONE', severity: 'None' }))).toBe('benign');
  });
});

// ============================================================================
// combineVerdict — three policies
// ============================================================================

describe('combineVerdict', () => {
  describe('structural-only', () => {
    it('passes the structural verdict through; never escalates', () => {
      expect(combineVerdict(true, 'attack', 'structural-only')).toEqual({ attack: true, escalate: false });
      expect(combineVerdict(false, 'attack', 'structural-only')).toEqual({ attack: false, escalate: false });
    });
  });

  describe('union', () => {
    it('auto-adds an analyst attack to a structural miss (recall ceiling)', () => {
      expect(combineVerdict(false, 'attack', 'union')).toEqual({ attack: true, escalate: false });
    });
    it('keeps a structural attack regardless of analyst', () => {
      expect(combineVerdict(true, 'benign', 'union')).toEqual({ attack: true, escalate: false });
    });
    it('escalates a mid-band abstention on an otherwise-clean artifact', () => {
      expect(combineVerdict(false, 'abstain', 'union')).toEqual({ attack: false, escalate: true });
    });
    it('benign analyst on a clean artifact stays benign, no escalation', () => {
      expect(combineVerdict(false, 'benign', 'union')).toEqual({ attack: false, escalate: false });
    });
  });

  describe('abstention-gated (CDS-024 safe — analyst never raises the auto-verdict)', () => {
    it('an analyst attack on a structural miss does NOT auto-flip; it escalates', () => {
      expect(combineVerdict(false, 'attack', 'abstention-gated')).toEqual({ attack: false, escalate: true });
    });
    it('an analyst abstain on a structural miss escalates', () => {
      expect(combineVerdict(false, 'abstain', 'abstention-gated')).toEqual({ attack: false, escalate: true });
    });
    it('structural attack stands; no redundant escalation', () => {
      expect(combineVerdict(true, 'attack', 'abstention-gated')).toEqual({ attack: true, escalate: false });
    });
    it('both clean: benign, no escalation', () => {
      expect(combineVerdict(false, 'benign', 'abstention-gated')).toEqual({ attack: false, escalate: false });
    });
  });

  it('abstention-gated auto-verdict always equals structural-only auto-verdict (FPR is preserved)', () => {
    for (const s of [true, false]) {
      for (const a of ['attack', 'benign', 'abstain'] as const) {
        expect(combineVerdict(s, a, 'abstention-gated').attack).toBe(
          combineVerdict(s, a, 'structural-only').attack,
        );
      }
    }
  });
});

// ============================================================================
// helpers / invariants
// ============================================================================

describe('helpers', () => {
  it('namesAttackClass distinguishes real classes from none/benign', () => {
    expect(namesAttackClass({ attackClass: 'tool_abuse', severity: 'high' })).toBe(true);
    expect(namesAttackClass({ attackClass: 'none', severity: null })).toBe(false);
    expect(namesAttackClass({ attackClass: 'benign', severity: null })).toBe(false);
  });

  it('isKnownAttackClass gates auto-attack to the canonical vocabulary only', () => {
    expect(isKnownAttackClass({ attackClass: 'privilege_escalation', severity: null })).toBe(true);
    expect(isKnownAttackClass({ attackClass: 'heartbeat_rce', severity: null })).toBe(true);
    // Prose / unknown is "named" but not "known".
    expect(namesAttackClass({ attackClass: 'Privilege Escalation / RCE', severity: null })).toBe(true);
    expect(isKnownAttackClass({ attackClass: 'Privilege Escalation / RCE', severity: null })).toBe(false);
    expect(KNOWN_ATTACK_CLASSES.has('privilege_escalation')).toBe(true);
  });

  it('exported sets carry the expected members', () => {
    expect(NON_ATTACK_CLASSES.has('none')).toBe(true);
    expect(NON_ATTACK_CLASSES.has('benign')).toBe(true);
    expect(HIGH_SEVERITIES.has('critical')).toBe(true);
    expect(HIGH_SEVERITIES.has('high')).toBe(true);
    expect(HIGH_SEVERITIES.has('medium')).toBe(false);
  });
});
