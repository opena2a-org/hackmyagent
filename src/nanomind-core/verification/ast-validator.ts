/**
 * AST Behavioral Validator
 *
 * Tests whether the SecurityAST's claims hold under behavioral simulation.
 * The AST says what an artifact DECLARES and what NanoMind INFERS.
 * The validator OBSERVES what the artifact actually DOES.
 *
 * This is the third leg of defense-in-depth:
 *   1. Static analysis: pattern matching on raw text
 *   2. NanoMind AST: semantic understanding of intent
 *   3. Behavioral validation: observation of actual behavior
 *
 * All three must agree for high-confidence classification.
 *
 * Security: even if both static and NanoMind are fooled,
 * behavioral observation catches the actual behavior.
 */

import type { SecurityAST, Capability, Constraint, RiskSurface } from '../types.js';
import { SimulationEngine, parseSkillProfile } from '../../simulation/engine.js';
import type { SimulationResult } from '../../simulation/types.js';
import { assertASTIntegrity } from '../security/defense-in-depth.js';

// ============================================================================
// Validation Result
// ============================================================================

export interface ASTValidationResult {
  /** Did the artifact behave as the AST declared? */
  valid: boolean;
  /** Validation verdicts per claim */
  claims: ClaimValidation[];
  /** Behavioral simulation result */
  simulation: SimulationResult | null;
  /** Overall confidence in the AST's accuracy */
  astAccuracy: number; // 0-1
  /** Discrepancies between AST claims and observed behavior */
  discrepancies: Discrepancy[];
  durationMs: number;
}

export interface ClaimValidation {
  claim: string;
  type: 'capability' | 'constraint' | 'intent' | 'scope';
  astSays: string;
  behaviorShows: string;
  validated: boolean;
  confidence: number;
}

export interface Discrepancy {
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  astClaim: string;
  observedBehavior: string;
}

// ============================================================================
// AST Validator
// ============================================================================

/**
 * Validate an AST's claims against behavioral simulation.
 *
 * @param ast - The compiled SecurityAST to validate
 * @param rawContent - The original artifact content (for simulation)
 * @param verifier - AST signature verifier
 */
export async function validateAST(
  ast: SecurityAST,
  rawContent: string,
  verifier: (ast: SecurityAST) => boolean,
): Promise<ASTValidationResult> {
  const startMs = Date.now();

  // Verify AST integrity first
  assertASTIntegrity(ast, verifier);

  const claims: ClaimValidation[] = [];
  const discrepancies: Discrepancy[] = [];

  // Run behavioral simulation
  const sim = new SimulationEngine();
  const profile = parseSkillProfile(rawContent, ast.artifactPath ?? 'unknown');
  let simulation: SimulationResult | null = null;

  try {
    simulation = await sim.runLayer3(profile);
  } catch {
    // Simulation failed -- validate AST against heuristics only
  }

  // Validate capability claims
  validateCapabilities(ast, simulation, claims, discrepancies);

  // Validate constraint claims
  validateConstraints(ast, simulation, claims, discrepancies);

  // Validate intent classification
  validateIntent(ast, simulation, claims, discrepancies);

  // Validate scope claims
  validateScope(ast, simulation, claims, discrepancies);

  // Compute overall accuracy
  const validated = claims.filter(c => c.validated).length;
  const astAccuracy = claims.length > 0 ? validated / claims.length : 1;

  return {
    valid: discrepancies.filter(d => d.severity === 'critical').length === 0,
    claims,
    simulation,
    astAccuracy,
    discrepancies,
    durationMs: Date.now() - startMs,
  };
}

// ============================================================================
// Claim Validators
// ============================================================================

function validateCapabilities(
  ast: SecurityAST,
  sim: SimulationResult | null,
  claims: ClaimValidation[],
  discrepancies: Discrepancy[],
): void {
  // Claim: declared capabilities are the ONLY capabilities exercised
  const declaredNames = new Set(ast.declaredCapabilities.map(c => c.name));
  const inferredUndeclared = ast.inferredCapabilities.filter(c => c.inferred && !c.declared);

  // Check if simulation found undeclared behavior
  if (sim) {
    const failedScopes = sim.failedProbes.filter(p => p.category === 'scope_expansion');
    if (failedScopes.length > 0 && inferredUndeclared.length === 0) {
      // Simulation found scope expansion that AST didn't predict
      discrepancies.push({
        description: 'Simulation detected scope expansion not predicted by AST',
        severity: 'high',
        astClaim: 'No undeclared capabilities',
        observedBehavior: `${failedScopes.length} scope expansion probe(s) failed`,
      });
    }
  }

  for (const cap of ast.declaredCapabilities) {
    claims.push({
      claim: `Capability: ${cap.name}`,
      type: 'capability',
      astSays: `Declared, risk level: ${cap.riskLevel}`,
      behaviorShows: sim ? 'Simulation ran' : 'No simulation data',
      validated: true, // Declared capabilities are accepted
      confidence: 0.8,
    });
  }

  for (const cap of inferredUndeclared) {
    claims.push({
      claim: `Undeclared capability: ${cap.name}`,
      type: 'capability',
      astSays: `Inferred but not declared, risk: ${cap.riskLevel}`,
      behaviorShows: sim?.failedProbes.some(p => p.category === 'scope_expansion')
        ? 'Simulation confirms scope expansion'
        : 'Not confirmed by simulation',
      validated: false,
      confidence: 0.6,
    });

    if (cap.riskLevel === 'critical' || cap.riskLevel === 'high') {
      discrepancies.push({
        description: `High-risk undeclared capability: ${cap.name}`,
        severity: cap.riskLevel === 'critical' ? 'critical' : 'high',
        astClaim: `${cap.name} is inferred but not declared`,
        observedBehavior: cap.evidence ?? 'Inferred from content analysis',
      });
    }
  }
}

function validateConstraints(
  ast: SecurityAST,
  sim: SimulationResult | null,
  claims: ClaimValidation[],
  discrepancies: Discrepancy[],
): void {
  for (const constraint of ast.declaredConstraints) {
    // Check if simulation tested override resistance
    const overrideProbes = sim?.failedProbes.filter(p => p.category === 'override_resistance') ?? [];
    const overrideResisted = sim?.passedProbes.filter(p => p.category === 'override_resistance') ?? [];

    if (constraint.domain === 'behavioral_constraint' || constraint.domain === 'capability_boundary') {
      const holds = overrideResisted.length >= overrideProbes.length;

      claims.push({
        claim: `Constraint: ${constraint.text.slice(0, 60)}...`,
        type: 'constraint',
        astSays: `Enforceability: ${(constraint.enforceability * 100).toFixed(0)}%, bypass risk: ${(constraint.bypassRisk * 100).toFixed(0)}%`,
        behaviorShows: sim
          ? (holds ? 'Constraint held under simulation probes' : 'Constraint FAILED under simulation probes')
          : 'No simulation data',
        validated: holds,
        confidence: sim ? 0.85 : 0.5,
      });

      if (!holds && sim) {
        discrepancies.push({
          description: `Constraint bypassed: "${constraint.text.slice(0, 60)}..."`,
          severity: 'high',
          astClaim: `Constraint with ${(constraint.enforceability * 100).toFixed(0)}% enforceability`,
          observedBehavior: `${overrideProbes.length} override probe(s) succeeded`,
        });
      }
    }
  }

  // Check: AST says no constraints, simulation confirms vulnerability
  if (ast.declaredConstraints.length === 0 && sim?.verdict === 'MALICIOUS') {
    discrepancies.push({
      description: 'No governance constraints and simulation confirms malicious behavior',
      severity: 'critical',
      astClaim: 'Zero constraints declared',
      observedBehavior: `Simulation verdict: MALICIOUS (${(sim.confidence * 100).toFixed(0)}% confidence)`,
    });
  }
}

function validateIntent(
  ast: SecurityAST,
  sim: SimulationResult | null,
  claims: ClaimValidation[],
  discrepancies: Discrepancy[],
): void {
  if (!sim) {
    claims.push({
      claim: `Intent: ${ast.intentClassification}`,
      type: 'intent',
      astSays: `${ast.intentClassification} (${(ast.intentConfidence * 100).toFixed(0)}% confidence)`,
      behaviorShows: 'No simulation data to verify',
      validated: true, // Accept AST without simulation
      confidence: ast.intentConfidence * 0.7, // Lower confidence without behavioral verification
    });
    return;
  }

  // Compare AST intent with simulation verdict
  const astIntent = ast.intentClassification;
  const simVerdict = sim.verdict.toLowerCase();

  const intentMap: Record<string, string[]> = {
    benign: ['clean'],
    suspicious: ['suspicious', 'clean'],
    malicious: ['malicious', 'suspicious'],
  };

  const agrees = intentMap[astIntent]?.includes(simVerdict) ?? false;

  claims.push({
    claim: `Intent: ${astIntent}`,
    type: 'intent',
    astSays: `${astIntent} (${(ast.intentConfidence * 100).toFixed(0)}% confidence)`,
    behaviorShows: `Simulation: ${sim.verdict} (${(sim.confidence * 100).toFixed(0)}% confidence)`,
    validated: agrees,
    confidence: agrees ? Math.max(ast.intentConfidence, sim.confidence) : 0.3,
  });

  if (!agrees) {
    // Intent disagreement
    const severity = astIntent === 'benign' && simVerdict === 'malicious' ? 'critical' : 'high';
    discrepancies.push({
      description: `AST says ${astIntent} but simulation says ${sim.verdict}`,
      severity,
      astClaim: `Intent: ${astIntent} (${(ast.intentConfidence * 100).toFixed(0)}%)`,
      observedBehavior: `Simulation: ${sim.verdict} (${(sim.confidence * 100).toFixed(0)}%, ${sim.failedProbes.length} failed probes)`,
    });
  }
}

function validateScope(
  ast: SecurityAST,
  sim: SimulationResult | null,
  claims: ClaimValidation[],
  discrepancies: Discrepancy[],
): void {
  // Check semantic delta from simulation
  if (sim && sim.semanticDelta > 0.5) {
    claims.push({
      claim: 'Scope: behavior matches declared purpose',
      type: 'scope',
      astSays: `Purpose: "${ast.declaredPurpose.slice(0, 60)}"`,
      behaviorShows: `Semantic delta: ${(sim.semanticDelta * 100).toFixed(0)}% divergence from declared purpose`,
      validated: false,
      confidence: 0.7,
    });

    discrepancies.push({
      description: 'Observed behavior significantly diverges from declared purpose',
      severity: sim.semanticDelta > 0.7 ? 'high' : 'medium',
      astClaim: `Purpose: "${ast.declaredPurpose.slice(0, 60)}"`,
      observedBehavior: `${(sim.semanticDelta * 100).toFixed(0)}% semantic divergence`,
    });
  } else {
    claims.push({
      claim: 'Scope: behavior matches declared purpose',
      type: 'scope',
      astSays: `Purpose: "${ast.declaredPurpose.slice(0, 60)}"`,
      behaviorShows: sim
        ? `Semantic delta: ${((sim.semanticDelta ?? 0) * 100).toFixed(0)}% (within acceptable range)`
        : 'No simulation data',
      validated: true,
      confidence: sim ? 0.85 : 0.5,
    });
  }
}
