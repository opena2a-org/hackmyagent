/**
 * Every payload a command sends to the OpenA2A Registry or to its
 * contribution endpoint, built from the run's own result.
 *
 * One builder per send kind. A builder takes what the run produced (its scan
 * result, its settled outcome, its report, the scanned directory and the
 * times the run recorded for its scan) and reads nothing else: not the
 * working directory, not the clock. src/cli.ts calls the builder and hands
 * its return value to the sender, and builds no payload field itself
 * (__tests__/registry/outbound-payload-census.test.ts reads src/cli.ts for
 * that).
 *
 * The values that once reached the registry from a send site in src/cli.ts
 * without coming from the run: a repository URL or target name with its
 * user name, password, query string or fragment; a tree hash of the shell's
 * working directory; a time of sending in place of the time of the scan; an
 * empty findings list for a scan with findings; a constant severity or
 * verdict. Each builder below derives those fields from the run instead.
 */
import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { join, resolve, basename } from 'path';
import { VERSION } from '../index';
import type { ScanResult, SecurityFindingDraft } from '../hardening/security-check';
import type { SecurityFinding, Severity } from '../hardening';
import { assertRedactionProvenance, emitFindings } from '../hardening/finding-emit';
import { wireStatus, type SettledOutcome } from '../hardening/settled-outcome';
import type { MeasuredFinding } from '../ui/verdict-band';
import { CONTROL_DEFS, type SoulScanResult } from '../soul';
import type { AttackReport } from '../attack';
import type { DetectResult } from '../scanner/detect';
import { buildScanEvent, eventPackage, type ContributionEvent } from '../telemetry/contribute';
import type { PendingScan } from '../telemetry/pending-scans';
import type { WireNarrativePublishOptions } from '../narrative/wire-publish';
import { isLocalGitRemote, scanNameWithoutUserinfo, withoutUrlQueryAndFragment, withoutUrlUserinfo } from '../check/url-userinfo';
import { computeTreeHash, type PublishScanData } from './publish';
import {
  buildAttackReport,
  buildCommunityAttackReport,
  buildCommunityReport,
  buildScanReport,
  type CIScanResultParams,
  type CommunityScanPayload,
  type ScanReportPayload,
} from './client';
import { buildPatchBody, type StubEvidence, type StubPatchBody } from './stub-writeback';

// ---------------------------------------------------------------------------
// The scanned target's identity
// ---------------------------------------------------------------------------

/** The package name in `<dir>/package.json`, else the directory's own name. */
export function resolvePackageName(targetDir: string): string | null {
  try {
    const pkg = JSON.parse(readFileSync(join(targetDir, 'package.json'), 'utf-8'));
    if (pkg.name) return pkg.name;
  } catch { /* ignore */ }
  // Fallback: the directory's name, "." resolved to the directory it names
  const name = basename(resolve(targetDir));
  // Skip names that are clearly not package names
  return name && name !== '.' && name !== '..' ? name : null;
}

/** The package version in `<dir>/package.json`. */
export function resolvePackageVersion(targetDir: string): string | null {
  try {
    const pkg = JSON.parse(readFileSync(join(targetDir, 'package.json'), 'utf-8'));
    if (pkg.version) return pkg.version;
  } catch { /* ignore */ }
  return null;
}

/** The package name in `<dir>/pyproject.toml` (Python projects). */
export function resolvePackageNamePyproject(targetDir: string): string | null {
  try {
    const content = readFileSync(join(targetDir, 'pyproject.toml'), 'utf-8');
    const nameMatch = content.match(/\[project\][\s\S]*?name\s*=\s*"([^"]+)"/);
    if (nameMatch) return nameMatch[1];
    const poetryMatch = content.match(/\[tool\.poetry\][\s\S]*?name\s*=\s*"([^"]+)"/);
    if (poetryMatch) return poetryMatch[1];
  } catch { /* ignore */ }
  return null;
}

/** The package version in `<dir>/pyproject.toml` (Python projects). */
export function resolvePackageVersionPyproject(targetDir: string): string | null {
  try {
    const content = readFileSync(join(targetDir, 'pyproject.toml'), 'utf-8');
    const versionMatch = content.match(/\[project\][\s\S]*?version\s*=\s*"([^"]+)"/);
    if (versionMatch) return versionMatch[1];
    const poetryMatch = content.match(/\[tool\.poetry\][\s\S]*?version\s*=\s*"([^"]+)"/);
    if (poetryMatch) return poetryMatch[1];
  } catch { /* ignore */ }
  return null;
}

/**
 * The repository URL of the scanned directory's git remote `origin`, as the
 * registry may store it: without the user name and password (or token) a CI
 * checkout often writes into it, and without a query string or fragment,
 * which name no repository and can carry a token too. An origin that is a
 * path on this machine names no repository the registry can link to, so it
 * yields no URL either.
 */
export function resolveRepoUrl(targetDir: string): { url: string | null; localPath: boolean } {
  try {
    const url = execSync('git remote get-url origin', {
      cwd: targetDir,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    if (url && isLocalGitRemote(url)) return { url: null, localPath: true };
    if (url) return { url: withoutUrlQueryAndFragment(withoutUrlUserinfo(url, 'git')), localPath: false };
  } catch { /* ignore */ }
  return { url: null, localPath: false };
}

const iso = (t: Date | string): string => new Date(t).toISOString();

// ---------------------------------------------------------------------------
// secure
// ---------------------------------------------------------------------------

/**
 * `secure --publish`: the hardening findings of the scan of `dir`, stamped
 * with the scan's time. Null when no package name can be read for `dir`.
 */
export function securePublishSubmission(dir: string, result: ScanResult): PublishScanData | null {
  const packageName = resolvePackageName(dir);
  if (!packageName) return null;
  return {
    packageName,
    packageVersion: resolvePackageVersion(dir) ?? undefined,
    directory: dir,
    hardeningFindings: result.findings,
    scanTimestamp: iso(result.timestamp),
  };
}

/** The package narrative `secure --publish` emits beside its publish, for a skill or MCP artifact. */
export function narrativeSubmission(
  targetDir: string,
  publishData: PublishScanData,
  result: ScanResult,
  registryUrl: string,
): WireNarrativePublishOptions {
  return {
    targetDir,
    packageName: publishData.packageName,
    packageVersion: publishData.packageVersion ?? '0.0.0',
    findings: result.findings,
    projectType: result.projectType,
    registryUrl,
  };
}

/** A community report, with the scan-token request that goes before it. */
export interface CommunityReportSubmission {
  packageName: string;
  tokenOptions: { packageType?: string; version?: string };
  report: CommunityScanPayload;
}

/**
 * `secure --registry-report`: the community report of the scan of `dir`,
 * dated at the end of the scan. Null when no package name can be read.
 */
export function secureCommunityReport(
  dir: string,
  result: ScanResult,
  settled: SettledOutcome,
  scanEndedAt: Date,
): CommunityReportSubmission | null {
  const packageName = resolvePackageName(dir);
  if (!packageName) return null;
  const version = resolvePackageVersion(dir) ?? undefined;
  return {
    packageName,
    tokenOptions: { version },
    report: buildCommunityReport(packageName, result.findings, { version }, settled, scanEndedAt),
  };
}

/** `secure --version-id`: the scan's report against a registry version, dated at the end of the scan. */
export function secureVersionReport(
  versionId: string,
  result: ScanResult,
  settled: SettledOutcome,
  scanEndedAt: Date,
): ScanReportPayload {
  return buildScanReport(versionId, result.findings, settled, scanEndedAt);
}

/** Why `secure --ci-publish` has nothing to send, or what it sends. */
export type CiScanSubmission =
  | { kind: 'no-package-name' }
  | { kind: 'local-origin' }
  | { kind: 'no-repo-url' }
  | { kind: 'ready'; params: CIScanResultParams; treeHashFailed: boolean };

/**
 * `secure --ci-publish`: the scan's counts and status from its settled
 * record, the content hash of the scanned tree, the repository URL of its
 * origin, and a scan id made from the end of the scan. The package name and
 * version are read from `displayDir` (the target as given); the origin and
 * the tree hash from `targetDir` (the tree scanned).
 */
export function ciScanSubmission(
  displayDir: string,
  targetDir: string,
  result: ScanResult,
  settled: SettledOutcome,
  scanDepth: string,
  scanEndedAt: Date,
  hmacSecret: string,
): CiScanSubmission {
  const packageName = resolvePackageName(displayDir) || resolvePackageNamePyproject(displayDir);
  const packageVersion = resolvePackageVersion(displayDir) || resolvePackageVersionPyproject(displayDir);
  const origin = resolveRepoUrl(targetDir);
  if (!packageName) return { kind: 'no-package-name' };
  if (origin.localPath) return { kind: 'local-origin' };
  if (!origin.url) return { kind: 'no-repo-url' };

  let contentHash = '';
  let treeHashFailed = false;
  try {
    contentHash = computeTreeHash(targetDir);
  } catch {
    treeHashFailed = true;
  }

  // #464 — the counts and status READ the settled record, never the
  // narrowed `result.findings` (a suppressed row cannot even appear there).
  const counts = settled.counts;
  return {
    kind: 'ready',
    treeHashFailed,
    params: {
      packageName,
      packageType: undefined,
      version: packageVersion ?? undefined,
      repoUrl: origin.url,
      scanId: `hma-ci-${scanEndedAt.getTime()}`,
      status: wireStatus(settled),
      criticalCount: counts.critical,
      highCount: counts.high,
      mediumCount: counts.medium,
      lowCount: counts.low,
      contentHash,
      scannerVersion: VERSION,
      hmacSecret,
      rawReport: {
        generator: 'hackmyagent',
        totalFindings: result.findings.length,
        failedFindings: counts.critical + counts.high + counts.medium + counts.low,
        scanDepth,
        // #464 — the settled record rides as ONE object built from the
        // in-memory record (carried, not yet persisted server-side).
        settledOutcome: settled,
      },
    },
  };
}

/**
 * The contribution event of a `secure` run: its settled figures, its
 * completed check count when the run kept one, stamped with the scan's time.
 * Null when no package name can be read for `targetDir`.
 */
export function secureContributionEvent(
  targetDir: string,
  result: ScanResult,
  settled: SettledOutcome,
  durationMs: number,
): ContributionEvent | null {
  const packageName = resolvePackageName(targetDir);
  if (!packageName) return null;
  // Completed check executions from the run's coverage record; omitted when
  // the run kept none (the event then omits `totalChecks`, #519).
  const completedChecks = result.coverage?.executions
    ? result.coverage.executions.filter((e) => e.completed).length
    : undefined;
  return buildScanEvent(packageName, targetDir, result.findings, durationMs, settled, completedChecks, iso(result.timestamp));
}

// ---------------------------------------------------------------------------
// scan-soul
// ---------------------------------------------------------------------------

const CRITICAL_CONTROLS = new Set(CONTROL_DEFS.filter((c) => c.critical).map((c) => c.id));

/**
 * The controls a `scan-soul` run evaluated, as findings: a control in a domain
 * the run skipped (by profile or by tier) is not one. A control the catalogue
 * marks critical is `critical`, the severity the run reports a missing one
 * at (its gate fails on it); any other control is `medium`.
 */
export function soulControlFindings(result: SoulScanResult): Array<SecurityFinding & { severity: Severity; passed: boolean }> {
  // Drafts, emitted below: these are published to the Registry.
  const drafts: SecurityFindingDraft[] = [];
  for (const domain of result.domains) {
    if (domain.skippedByProfile || domain.skippedByTier) continue;
    for (const ctrl of domain.controls) {
      drafts.push({
        checkId: ctrl.id,
        name: ctrl.name,
        description: '',
        category: domain.domain,
        severity: (CRITICAL_CONTROLS.has(ctrl.id) ? 'critical' : 'medium') as Severity,
        passed: ctrl.passed,
        message: '',
        fixable: false,
      });
    }
  }
  // Every draft above sets a severity and a pass state.
  return emitFindings(drafts) as Array<SecurityFinding & { severity: Severity; passed: boolean }>;
}

/**
 * `scan-soul --publish`: the controls the run evaluated, its score, and the
 * scan's time. Null when no package name can be read for `dir`.
 */
export function soulPublishSubmission(dir: string, result: SoulScanResult, scanStartedAt: Date): PublishScanData | null {
  const packageName = resolvePackageName(dir);
  if (!packageName) return null;
  return {
    packageName,
    packageVersion: resolvePackageVersion(dir) ?? undefined,
    directory: dir,
    soulResult: result,
    governanceFindings: soulControlFindings(result),
    runScore: {
      score: result.score,
      rawScore: result.rawScore ?? result.score,
      scoreClamped: result.scoreClamped ?? false,
    },
    scanTimestamp: iso(scanStartedAt),
  };
}

/** The contribution event of a `scan-soul` run, stamped with the scan's time. */
export function soulContributionEvent(
  targetDir: string,
  result: SoulScanResult,
  durationMs: number,
  scanStartedAt: Date,
): ContributionEvent | null {
  const packageName = resolvePackageName(targetDir);
  if (!packageName) return null;
  return buildScanEvent(packageName, targetDir, soulControlFindings(result), durationMs, undefined, undefined, iso(scanStartedAt));
}

// ---------------------------------------------------------------------------
// detect
// ---------------------------------------------------------------------------

/**
 * The contribution event of a `detect` run: its findings counted by their
 * severity, the verdict those severities make (critical fails, high warns),
 * the governance score it printed, its scan time and how long the scan took.
 * It carries no `totalChecks`: `detect` counts findings, not checks. Null
 * when the run reported no single-project result (a workspace listing, an
 * unreadable target) or no package name can be read for `targetDir`.
 */
export function detectContributionEvent(
  targetDir: string,
  result: DetectResult | undefined,
  durationMs: number,
): ContributionEvent | null {
  if (!result) return null;
  const packageName = resolvePackageName(targetDir);
  if (!packageName) return null;
  const count = (severity: string) => result.findings.filter((f) => f.severity === severity).length;
  const critical = count('critical');
  const high = count('high');
  return {
    type: 'scan_result',
    tool: 'hackmyagent',
    toolVersion: VERSION,
    timestamp: result.scanTimestamp,
    package: eventPackage(packageName, targetDir),
    scanSummary: {
      passed: 0,
      critical,
      high,
      medium: count('medium'),
      low: count('low'),
      score: result.summary.governanceScore,
      verdict: critical > 0 ? 'fail' : high > 0 ? 'warn' : 'pass',
      durationMs,
    },
  };
}

// ---------------------------------------------------------------------------
// attack
// ---------------------------------------------------------------------------

/** The name the registry gets for an attacked URL: without its userinfo, query string and fragment. */
export function attackTargetName(url: string): string {
  return withoutUrlQueryAndFragment(withoutUrlUserinfo(url, 'fetch'));
}

/** The report as the registry gets it: its `target` named as `attackTargetName` names it. */
function registryAttackReport(report: AttackReport): AttackReport {
  return { ...report, target: attackTargetName(report.target) };
}

/** `attack --registry-report`: the community report of the attack, dated at its end. */
export function attackCommunityReport(report: AttackReport, targetUrl: string): CommunityReportSubmission {
  const packageName = attackTargetName(targetUrl);
  return {
    packageName,
    tokenOptions: {},
    report: buildCommunityAttackReport(packageName, registryAttackReport(report), undefined, new Date(report.endTime)),
  };
}

/** `attack --version-id`: the attack's report against a registry version, dated at its end. */
export function attackVersionReport(versionId: string, report: AttackReport): ScanReportPayload {
  return buildAttackReport(versionId, registryAttackReport(report), new Date(report.endTime));
}

/**
 * `attack --publish`: the payload results, stamped with the attack's start.
 * No `directory`: the target is a URL, and the publish path hashes the
 * directory it is given as the content hash of what was scanned.
 */
export function attackPublishSubmission(report: AttackReport, targetUrl: string): PublishScanData {
  return {
    packageName: attackTargetName(targetUrl),
    attackReport: report,
    scanTimestamp: iso(report.startTime),
  };
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

/**
 * Categories that describe local dev-environment setup, not package security.
 * Findings in these categories are filtered from display when scanning a
 * *downloaded* package (npm pack, pip download, git clone to temp dir), and
 * from what `check` shares. They remain visible when scanning a user's own
 * project directory.
 */
export const PACKAGE_SCAN_LOCAL_ONLY_CATEGORIES = new Set([
  'git',
  'permissions',
  'environment',
  'logging',
  'claude-code',
  'cursor',
  'vscode',
]);

/**
 * The name a `check` share is sent under: without a git URL's user name and
 * password, query string and fragment. A name made from a git URL with a
 * query (`gitlab.com/org/repo.git?ref=main`) keeps the `.git` the query hid
 * from the display name; it is dropped with the query, so the share carries
 * the name the same URL gets without one. A package name holds no `?` or
 * `#` and is sent as it is.
 */
export function checkShareName(name: string): string {
  const named = scanNameWithoutUserinfo(name);
  const cut = named.search(/[?#]/);
  return cut === -1 ? named : named.slice(0, cut).replace(/\.git$/, '');
}

/**
 * The submission `check` sends to the community registry for a scan. A
 * publish that fails queues this same object, so the retry sends what the
 * first attempt sent: the scan's findings, the scan's time, the version
 * that scanned.
 */
export function checkShareSubmission(
  name: string,
  result: { score: number; maxScore: number; projectType: string; findings: SecurityFinding[]; timestamp: Date },
): PendingScan {
  assertRedactionProvenance(result.findings, 'registry-publish-scan');
  return {
    name: checkShareName(name),
    score: result.score,
    maxScore: result.maxScore,
    projectType: result.projectType,
    toolVersion: VERSION,
    findings: result.findings
      .filter((f) => !PACKAGE_SCAN_LOCAL_ONLY_CATEGORIES.has(f.category))
      // #458 — result.findings holds measured records only (the render filter in
      // scanner.ts drops a not-applicable record, which has no pass/fail state
      // and no severity); this narrows the type to say both and drops nothing:
      // the parity test pins it.
      .filter((f): f is MeasuredFinding & { passed: boolean } => typeof f.passed === 'boolean' && f.severity !== undefined)
      .map((f) => ({
        checkId: f.checkId,
        name: f.name,
        severity: f.severity,
        passed: f.passed,
        message: f.message,
        category: f.category,
      })),
    scanTimestamp: iso(result.timestamp),
  };
}

/**
 * A queued share as it is sent again: its own findings, scan time and tool
 * version, under the name `checkShareName` gives it (an earlier version
 * queued names with a git URL's user name and password, or its query).
 */
export function queuedShareResend(queued: PendingScan): PendingScan {
  return { ...queued, name: checkShareName(queued.name) };
}

/** The body `check` publishes for a share, new or queued. */
export function checkSharePayload(scan: PendingScan) {
  return {
    name: scan.name,
    score: scan.score,
    maxScore: scan.maxScore,
    projectType: scan.projectType,
    tool: 'hackmyagent',
    toolVersion: scan.toolVersion,
    findings: scan.findings,
    scanTimestamp: scan.scanTimestamp,
  };
}

// ---------------------------------------------------------------------------
// usage telemetry and stub write-back
// ---------------------------------------------------------------------------

/** A command's usage event: whether it did its job, and how long it ran. */
export function usageEvent(succeeded: boolean, startedAt: number, endedAt: number): { success: boolean; durationMs: number } {
  return { success: succeeded, durationMs: endedAt - startedAt };
}

/** The PATCH body that moves a registry stub to `status`. */
export function stubTransitionBody(status: string, reason: string | undefined, evidence: StubEvidence | undefined): StubPatchBody {
  return buildPatchBody({ status, reason, evidence });
}
