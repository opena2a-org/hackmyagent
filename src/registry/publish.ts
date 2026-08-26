/**
 * ATP Publish Flow — Push scan results to the OpenA2A Registry.
 *
 * Supports two paths:
 *   1. Claimed agent: reads Ed25519 keypair from ~/.opena2a/keys/, signs payload, full weight (1.0x)
 *   2. Community fallback: no auth, results have lower weight (0.5x)
 *
 * Used by the --publish flag on secure, attack, and scan-soul commands.
 */

import { createHash } from 'crypto';
import { readdirSync, statSync, readFileSync } from 'fs';
import { join, relative } from 'path';
import type { SecurityFinding, Severity } from '../hardening';
import { assertRedactionProvenance } from '../hardening/finding-emit';
import { calculateSecurityScore } from '../hardening';
import { clampScoreToVerdictBand, countsAgainstScore, isMeasured } from '../ui/verdict-band';
import type { AttackReport } from '../attack';
import type { SoulScanResult } from '../soul';
import type { BenchmarkResult } from '../benchmarks';
import { RegistryClient, type UnifiedPublishPayload, type UnifiedFinding } from './client';
import { reportFindings, reportRemediation } from './remediation';
import type { SettledOutcome } from '../hardening/settled-outcome';
import { firstPartySignerFromEnv } from '@opena2a/registry-client';

/**
 * Compute a deterministic tree hash of a directory's contents.
 * Used by the CAAT pipeline to deduplicate scans across forks:
 * same content = same hash = cache hit.
 *
 * Walks all files (excluding common non-source dirs), sorts entries,
 * and produces a SHA-256 over "relPath:fileHash\n" lines.
 */
export function computeTreeHash(directory: string): string {
  const entries: string[] = [];
  const skipDirs = new Set(['.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build']);

  function walk(dir: string) {
    let dirEntries;
    try {
      dirEntries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // Skip unreadable directories
    }
    for (const entry of dirEntries) {
      if (skipDirs.has(entry.name)) continue;
      const fullPath = join(dir, entry.name);
      try {
        if (entry.isDirectory()) {
          walk(fullPath);
        } else {
          const relPath = relative(directory, fullPath);
          const fileHash = createHash('sha256').update(readFileSync(fullPath)).digest('hex');
          entries.push(`${relPath}:${fileHash}`);
        }
      } catch {
        // Skip unreadable files (permission errors, special files, etc.)
      }
    }
  }

  walk(directory);
  entries.sort();

  const h = createHash('sha256');
  for (const entry of entries) {
    h.update(entry + '\n');
  }
  return h.digest('hex');
}

/** Result of reading a keypair from ~/.opena2a/keys/ */
export interface AgentKeypair {
  publicKey: string;
  privateKey: string;
  agentId?: string;
}

/** Composite scan data collected from all scan types for publishing */
export interface PublishScanData {
  packageName: string;
  packageVersion?: string;
  packageType?: string;
  directory: string;
  /** Hardening scan findings (from `secure` command) */
  hardeningFindings?: SecurityFinding[];
  /** Attack scan report (from `attack` command) */
  attackReport?: AttackReport;
  /** SOUL governance scan result (from `scan-soul` command) */
  soulResult?: SoulScanResult;
  /** OASB benchmark result (from `secure -b oasb-1`) */
  oasbResult?: BenchmarkResult;
  /** CAAT tree hash — deterministic content hash of the scanned directory */
  treeHash?: string;
}

/** Result returned after publishing to registry */
export interface PublishResult {
  success: boolean;
  scanId: string;
  profileUrl: string;
  status: string;
  isCommunity: boolean;
  error?: string;
}

/**
 * Read the agent's Ed25519 keypair from ~/.opena2a/keys/.
 * Returns null if no keypair exists (agent not claimed).
 *
 * The keys directory can be overridden via OPENA2A_HOME env var
 * (defaults to ~/.opena2a).
 */
export function readAgentKeypair(): AgentKeypair | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const os = require('os');

    const opena2aHome = process.env.OPENA2A_HOME || path.join(os.homedir(), '.opena2a');
    const keysDir = path.join(opena2aHome, 'keys');
    if (!fs.existsSync(keysDir)) {
      return null;
    }

    const pubKeyPath = path.join(keysDir, 'agent.pub');
    const privKeyPath = path.join(keysDir, 'agent.key');
    const agentIdPath = path.join(keysDir, 'agent-id');

    const publicKey = fs.readFileSync(pubKeyPath, 'utf-8').trim();
    const privateKey = fs.readFileSync(privKeyPath, 'utf-8').trim();
    let agentId: string | undefined;
    try {
      agentId = fs.readFileSync(agentIdPath, 'utf-8').trim();
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code && code !== 'ENOENT') throw e;
    }

    return { publicKey, privateKey, agentId };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    // ENOENT = no keys yet (normal — user hasn't run init). Other errors
    // (EACCES, EISDIR) surface as "unable to read" so the user gets a
    // real error instead of a misleading "run init" prompt.
    if (code === 'ENOENT' || !code) return null;
    throw e;
  }
}

/**
 * Sign a payload string with the agent's Ed25519 private key.
 * Returns the base64-encoded signature, or null if signing fails.
 */
export function signPayload(payload: string, privateKeyPem: string): string | null {
  try {
    const crypto = require('crypto');
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const signature = crypto.sign(null, Buffer.from(payload), privateKey);
    return signature.toString('base64');
  } catch {
    return null;
  }
}

/**
 * Build a unified publish payload matching the POST /api/v1/trust/publish contract.
 * Combines results from hardening, attack, SOUL, and OASB scans into a single payload.
 */
export function buildPublishPayload(data: PublishScanData, toolVersion: string, settled?: SettledOutcome): UnifiedPublishPayload {
  // Publish-boundary read (unit 2): every finding leaving for the Registry
  // must carry redaction provenance. The payload built below projects the
  // fields away (wire-schema carry is a separate unit), so the read runs on
  // the INPUT, where the provenance still exists to be read.
  assertRedactionProvenance(data, 'registry-publish');
  const scanTimestamp = new Date().toISOString();
  const findings: UnifiedFinding[] = [];

  // Map hardening findings
  if (data.hardeningFindings) {
    for (const f of data.hardeningFindings) {
      // #458 — a not-applicable record is not a finding on the wire: the OASB-1
      // status channel carries not-applicable; the signed publish canonical
      // carries measured findings only.
      if (!isMeasured(f)) continue;
      findings.push({
        checkId: f.checkId,
        name: f.name,
        severity: f.severity,
        // A fix the verification pass could not confirm is NOT passed. Folding
        // every `fixed` into `passed` here discarded `fixVerified` before the
        // score, the clamp and the verdict ever saw it, so the fixture the
        // terminal reports as `69/100 ... exit 1` published as
        // `score 100 / verdict pass / 0 failed checks` — and `score` is inside
        // the signed strong canonical below.
        passed: !countsAgainstScore(f),
        message: f.description,
        category: f.category,
      });
    }
  }

  // Map attack results as findings
  if (data.attackReport) {
    for (const r of data.attackReport.results) {
      findings.push({
        checkId: r.payload.id,
        name: `Attack: ${r.payload.category} - ${r.payload.id}`,
        severity: r.payload.severity,
        passed: !r.success,
        message: r.success ? (r.response?.substring(0, 500) || 'Attack succeeded') : 'Attack blocked',
        category: 'attack',
        attackClass: r.payload.category,
      });
    }
  }

  // Map SOUL control results as findings
  if (data.soulResult && (data.soulResult as any).controls) {
    for (const c of (data.soulResult as any).controls) {
      findings.push({
        checkId: c.id || c.checkId,
        name: c.name,
        severity: c.severity || 'medium',
        passed: c.passed,
        message: c.description || c.message || '',
        category: 'governance',
      });
    }
  }

  // Use canonical scoring formula (exponential decay + 0.4x governance weight),
  // then apply the #259 verdict-band clamp.
  //
  // This was the last bare `calculateSecurityScore` on a published surface.
  // The #259 note in `hardening/scanner.ts` states the clamp is applied in the
  // scanner "so `--json` and the Registry carry the same figure the terminal
  // shows" — but this path builds its own composite from its own merged
  // findings and never went through `applyScore()`, so the Registry received
  // the pre-clamp number (76 where the CLI showed 69) with no `rawScore` to
  // reveal the discrepancy. `score` is part of the signed strong canonical
  // below, so the signature would have attested a figure the tool never
  // displayed.
  // #464 — with a settled record (the `secure --publish` arms), every figure
  // is READ from it, never recomputed here: the recomputation over the
  // narrowed `findings` list is what published `score 100 / verdict pass /
  // 0 failed checks` for the run the terminal reported `69/100 ... exit 1`.
  // The local computation remains ONLY for callers with no settled `secure`
  // run behind them (the `attack` registry arm's merged payload).
  if (settled?.verdict === null) {
    // Fail closed: `outboundAllowed` withholds exit-2 runs before this call;
    // a null-verdict record reaching a wire is a caller bug, not a payload.
    throw new Error('a run at EXIT_UNMEASURED never publishes (#464)');
  }
  const { score: localRawScore } = calculateSecurityScore(findings);
  const { score: localScore, clamped: localClamped } = clampScoreToVerdictBand(localRawScore, findings);
  const rawScore = settled ? (settled.rawScore ?? settled.score) : localRawScore;
  const score = settled ? settled.score : localScore;
  const scoreClamped = settled ? (settled.scoreClamped ?? false) : localClamped;
  const failedCritical = settled ? settled.counts.critical : findings.filter(f => !f.passed && f.severity === 'critical').length;
  const failedHigh = settled ? settled.counts.high : findings.filter(f => !f.passed && f.severity === 'high').length;
  const failedMedium = settled ? settled.counts.medium : findings.filter(f => !f.passed && f.severity === 'medium').length;
  const failedLow = settled ? settled.counts.low : findings.filter(f => !f.passed && f.severity === 'low').length;
  let verdict: 'pass' | 'warn' | 'fail';
  if (settled) {
    verdict = settled.verdict;
  } else if (failedCritical > 0 || failedHigh > 0) verdict = 'fail';
  else if (failedMedium > 0 || failedLow > 0) verdict = 'warn';
  else verdict = 'pass';

  // Build sub-reports from each scan type
  const subReports: Record<string, unknown> = {
    generator: 'hackmyagent',
    publishedVia: 'atp-publish',
  };

  if (data.hardeningFindings) {
    // #458 — the sub-report counts measured findings only, matching the wire
    // list above: a not-applicable record is in no denominator anywhere.
    // #464 — `passRate` is DELETED, not renamed: a second ratio beside the
    // settled score was the recomputation class this PR removes, and no
    // server reader exists (`hardening_pass_rate` is written by nothing in
    // the Registry's internal/).
    const measured = data.hardeningFindings.filter(isMeasured);
    const total = measured.length;
    const failed = measured.filter(f => countsAgainstScore(f)).length;
    subReports.hardening = {
      totalChecks: total,
      failedChecks: failed,
    };
  }

  if (data.attackReport) {
    subReports.attack = {
      riskScore: data.attackReport.riskScore,
      riskRating: data.attackReport.riskRating,
      totalPayloads: data.attackReport.summary.total,
      successfulAttacks: data.attackReport.summary.successful,
      blockedAttacks: data.attackReport.summary.blocked,
    };
  }

  if (data.soulResult) {
    subReports.soul = {
      score: data.soulResult.score,
      // #206 R2.4: publish rawScore + scoreClamped so the Registry can
      // distinguish "scoring rule changed across HMA versions" from
      // "the agent's governance got worse." Without both fields, a
      // dashboard plotting historical score sees a phantom regression
      // the moment HMA 0.23.5 clamps a previously-100 verdict to 74.
      rawScore: data.soulResult.rawScore,
      scoreClamped: data.soulResult.scoreClamped,
      conformance: data.soulResult.conformance,
      agentTier: data.soulResult.agentTier,
      totalControls: data.soulResult.totalControls,
      totalPassed: data.soulResult.totalPassed,
    };
  }

  if (data.oasbResult) {
    subReports.oasb = {
      compliance: data.oasbResult.compliance,
      rating: data.oasbResult.rating,
      l1Compliance: data.oasbResult.l1Compliance,
      l2Compliance: data.oasbResult.l2Compliance,
      l3Compliance: data.oasbResult.l3Compliance,
    };
  }

  // Compute content hash
  const canonical = [
    data.packageName,
    data.packageType || '',
    data.packageVersion || '',
    verdict,
    failedCritical,
    failedHigh,
    failedMedium,
    failedLow,
  ].join('|');
  const contentHash = createHash('sha256').update(canonical).digest('hex');

  const payload: UnifiedPublishPayload = {
    name: data.packageName,
    type: data.packageType,
    version: data.packageVersion,
    score,
    // Only carried when the clamp actually fired, so an unclamped publish
    // stays byte-identical to what the Registry received before (#259).
    ...(scoreClamped ? { rawScore, scoreClamped } : {}),
    maxScore: 100,
    tool: 'hackmyagent',
    toolVersion,
    findings,
    scanTimestamp,
    verdict,
    subReports,
    contentHash,
    // #464 — the settled record rides the wire: typed counts the server can
    // trust instead of re-deriving from the narrowed findings[], plus the
    // measurement disclosure. Absent on the non-settled (attack) path, so an
    // unsettled publish stays byte-identical to what the Registry received.
    ...(settled
      ? {
          criticalCount: settled.counts.critical,
          highCount: settled.counts.high,
          mediumCount: settled.counts.medium,
          lowCount: settled.counts.low,
          measured: settled.measured,
          exitCode: settled.exitCode,
          coverage: settled.coverage,
          ...(settled.suppressed ? { suppressed: settled.suppressed } : {}),
          ...(settled.outOfScope ? { outOfScope: settled.outOfScope } : {}),
          schemaVersion: settled.schemaVersion,
        }
      : {}),
  };

  if (data.treeHash) {
    payload.treeHash = data.treeHash;
  }

  return payload;
}

/**
 * Publish scan results to the OpenA2A Registry.
 *
 * Flow:
 *   1. Read keypair from ~/.opena2a/keys/ (if claimed)
 *   2. Build unified payload from scan data
 *   3. Sign payload if keypair exists
 *   4. POST to registry (claimed or community path)
 */
export async function publishScanResults(
  data: PublishScanData,
  registryUrl: string,
  settled?: SettledOutcome,
): Promise<PublishResult> {
  const keypair = readAgentKeypair();

  // First-party scanner provenance: our official batch scanner signs the strong canonical
  // with a DEDICATED Ed25519 key supplied via env (HMA_SCANNER_SIGNING_KEY, Secretless —
  // never the per-user ~/.opena2a identity). This is the only path that unlocks
  // source=first_party_scanner at the registry. End-user `--publish` runs (no env key)
  // keep the existing claimed-agent / community behavior.
  const firstPartySigner = firstPartySignerFromEnv({
    keyEnv: 'HMA_SCANNER_SIGNING_KEY',
    source: 'first_party_scanner',
  });

  const isCommunity = !keypair && !firstPartySigner;

  if (isCommunity) {
    console.log("No signing keys found at ~/.opena2a/keys/. Run 'opena2a claim <package>' to create keys for full-weight publishing. Submitting as community contribution (0.5x weight).");
  }

  // Compute CAAT tree hash from the scanned directory if not already set
  if (!data.treeHash && data.directory) {
    try {
      data.treeHash = computeTreeHash(data.directory);
    } catch {
      // Tree hash computation is non-fatal (e.g., permission errors)
    }
  }

  // Read tool version from package.json
  let toolVersion = '0.0.0';
  try {
    const pkgPath = require('path').join(__dirname, '../../package.json');
    toolVersion = require(pkgPath).version;
  } catch {
    // Fallback version
  }

  const payload = buildPublishPayload(data, toolVersion, settled);

  // Sign and include identity in body (not headers).
  let signedFirstParty = false;
  if (firstPartySigner) {
    // First-party scanner: sign the registry's STRONG canonical
    // (name|version|score|maxScore|source|nonce|signedAt) with the raw scanner key.
    // These override any claimed-agent PEM signature — the registry allowlist matches a
    // raw 32-byte key over this canonical, not a full-JSON PEM signature. Signing must
    // never crash a publish: on any signer error, fall through to the claimed-agent /
    // community path below (the registry records that as community — fail-closed).
    try {
      const prov = firstPartySigner.sign({
        name: payload.name,
        version: payload.version,
        score: payload.score,
        maxScore: payload.maxScore,
      });
      payload.source = prov.source;
      payload.nonce = prov.nonce;
      payload.signedAt = prov.signedAt;
      payload.signature = prov.signature;
      payload.publicKey = prov.publicKey;
      if (keypair?.agentId) {
        payload.agentId = keypair.agentId;
      }
      signedFirstParty = true;
    } catch {
      // Degrade to community (or claimed-agent below).
    }
  }
  if (!signedFirstParty && keypair) {
    // Legacy claimed-agent path: full-JSON PEM signature, surfaced as X-Agent-Signature
    // on the legacy endpoint. Does not unlock privileged provenance (publishes as community).
    const payloadString = JSON.stringify(payload);
    const signature = signPayload(payloadString, keypair.privateKey);
    if (signature) {
      payload.signature = signature;
      payload.publicKey = keypair.publicKey;
    }
    if (keypair.agentId) {
      payload.agentId = keypair.agentId;
    }
  }

  try {
    const client = new RegistryClient({ registryUrl, apiKey: '' });

    // Request a scan token before submitting (required by registry)
    const tokenResponse = await client.requestScanToken(data.packageName, {
      packageType: data.packageType,
      version: data.packageVersion,
    });
    const scanToken = tokenResponse?.scanToken;

    const result = await client.reportPublishResult(payload, scanToken);

    if (result.publishId) {
      console.log(`Published to registry (${result.publishId.slice(0, 8)})`);
    }

    // Report remediation tracking (non-blocking)
    if (data.hardeningFindings) {
      // #464 — the settled score, never a second ratio: the pass-fraction
      // computed here was the third spelling of the run's score on one wire
      // (`initialScore` / `rescanScore` disagreed with the published `score`
      // and with the terminal). The ratio remains only for the non-settled
      // (attack) path.
      const score = settled
        ? settled.score
        : data.hardeningFindings.length > 0
          ? Math.round(
              (data.hardeningFindings.filter(f => !countsAgainstScore(f)).length /
                data.hardeningFindings.length) *
                100,
            )
          : 100;

      try {
        await reportFindings(registryUrl, result.scanId, data.packageName, data.hardeningFindings, score);
        await reportRemediation(registryUrl, result.scanId, data.packageName, data.hardeningFindings, score);
      } catch {
        // Non-blocking -- remediation tracking should never fail the publish
      }
    }

    return {
      success: true,
      scanId: result.scanId,
      profileUrl: result.profileUrl,
      status: result.status,
      isCommunity,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return {
      success: false,
      scanId: `hma-publish-${Date.now()}`,
      profileUrl: `${registryUrl}/agents/${data.packageName}`,
      status: 'error',
      isCommunity,
      error: message,
    };
  }
}

/**
 * Format the publish result for terminal output.
 */
export function formatPublishOutput(
  result: PublishResult,
  data: PublishScanData,
  registryUrl: string,
): string {
  const lines: string[] = [];

  if (result.success) {
    lines.push('Published to ' + new URL(registryUrl).hostname);
    lines.push('  Agent: ' + data.packageName);
    lines.push('  Scan ID: ' + result.scanId);
    lines.push('  Status: ' + result.status);

    // Build summary of what was included
    const parts: string[] = [];
    if (data.hardeningFindings) {
      const failed = data.hardeningFindings.filter(f => countsAgainstScore(f));
      parts.push(`hardening (${failed.length} finding${failed.length === 1 ? '' : 's'})`);
    }
    if (data.oasbResult) {
      // #458 step 0: a benchmark run that measured nothing carries `null`.
      parts.push(data.oasbResult.compliance === null
        ? 'OASB (compliance not measured)'
        : `OASB (${data.oasbResult.compliance}% compliance)`);
    }
    if (data.soulResult) {
      parts.push(`SOUL (${data.soulResult.score}/100)`);
    }
    if (data.attackReport) {
      parts.push(`attack (${data.attackReport.riskRating} risk)`);
    }
    if (parts.length > 0) {
      lines.push('  Scans: ' + parts.join(', '));
    }

    lines.push('  Trust impact: score may increase on next recalculation');

    if (result.isCommunity) {
      lines.push('');
      lines.push('  Published as community scan (0.5x weight).');
      lines.push('  Run `opena2a claim` first for full weight (1.0x).');
    }

    lines.push('');
    lines.push('Profile: ' + result.profileUrl);
  } else {
    lines.push('Failed to publish to registry: ' + (result.error || 'unknown error'));
    lines.push('Scan results are still available locally.');
  }

  return lines.join('\n');
}
