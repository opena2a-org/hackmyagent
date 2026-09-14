/**
 * NanoMind Integrity Verifier
 *
 * Startup integrity verification that runs BEFORE any scanning or model loading.
 * Detects tampering of the CLI binary, NanoMind model files, and rule manifests.
 *
 * Three outcomes:
 *   CLEAN      -- All checks pass, proceed normally
 *   DEGRADE    -- Model integrity failed, fall back to heuristic scanning (warn user)
 *   QUARANTINE -- Package/dist integrity failed, refuse to output, exit code 3
 *
 * Design constraints:
 *   - Must complete in < 5ms for unmodified installations
 *   - Uses SHA-256 for all hashes, HMAC-SHA256 as Ed25519 fallback
 *   - Tamper-evident event chain (append-only JSONL with hash linking)
 *   - Model hash verified BEFORE loading into memory
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync, existsSync, appendFileSync, mkdirSync, readdirSync, lstatSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { escapePathForDisplay, escapeForDisplay } from '../../ui/display-safe';

// ============================================================================
// Types
// ============================================================================

export type IntegrityStatus = 'CLEAN' | 'QUARANTINE' | 'DEGRADE';

export interface IntegrityCheck {
  name: string;
  passed: boolean;
  reason?: string;
}

export interface IntegrityResult {
  status: IntegrityStatus;
  checks: IntegrityCheck[];
  durationMs: number;
}

export interface IntegrityManifest {
  version: string;
  files: Record<string, string>;        // relative path -> SHA-256 hash
  modelHash?: string;                    // expected GGUF model hash
  ruleCategories?: number;               // expected rule category count
  signature?: string;                    // HMAC-SHA256 or Ed25519 signature (hex)
}

export interface TamperEvent {
  seq: number;
  timestamp: string;
  eventType: 'startup' | 'check_pass' | 'check_fail' | 'tamper_detected' | 'degraded' | 'quarantine';
  detail: string;
  prevHash: string;                      // SHA-256 of previous event JSON (empty string for genesis)
}

// ============================================================================
// Constants
// ============================================================================

const NANOMIND_DIR = join(homedir(), '.nanomind');
const MODELS_DIR = join(NANOMIND_DIR, 'models');
const EVENT_CHAIN_PATH = join(NANOMIND_DIR, 'integrity-events.jsonl');
// No leading dot: the release artifact review (scripts/release-artifact-review.mjs)
// refuses any dotfile entry in the published tarball, and this file ships in it.
const MANIFEST_FILENAME = 'integrity-manifest.json';
const GENESIS_PREV_HASH = '0'.repeat(64);

// ============================================================================
// SHA-256 Utilities
// ============================================================================

export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256File(filePath: string): string {
  const content = readFileSync(filePath);
  return sha256(content);
}

/**
 * HMAC-SHA256 signature (fallback when Ed25519 keys are unavailable).
 * In production with Ed25519 keys, this would be replaced by Ed25519 sign/verify.
 */
export function hmacSign(data: string, key: string): string {
  return createHmac('sha256', key).update(data).digest('hex');
}

export function hmacVerify(data: string, key: string, expectedSig: string): boolean {
  const computed = hmacSign(data, key);
  if (computed.length !== expectedSig.length) return false;
  try {
    return timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(expectedSig, 'hex'));
  } catch {
    return false;
  }
}

// ============================================================================
// Manifest Operations
// ============================================================================

/**
 * Load the integrity manifest. The build script writes it to
 * `<packageRoot>/dist/integrity-manifest.json` (so it ships inside the
 * `dist/` tree that gets published). Look there first, then fall back to
 * `<packageRoot>/integrity-manifest.json` for any consumer that places
 * the manifest at the package root.
 *
 * Returns null when:
 *   - no manifest exists (first run or dev mode), or
 *   - a manifest path resolves to a symlink (rejected as a supply-chain
 *     attack vector — an attacker with write access to the install dir
 *     could redirect manifest resolution to an attacker-controlled file).
 *
 * Symlink rejection writes a stderr warning at every probed location so
 * the rejection is visible to operators, even though the verifier falls
 * through to dev-mode CLEAN. (Hard QUARANTINE on symlink would brick
 * legitimate dev workflows that symlink the manifest.)
 *
 * Internal exports (`__symlinkRejectedAtPath`) propagate the rejection
 * reason to verifyAll so the manifest_load check can record it.
 */
export function loadManifest(packageRoot: string): IntegrityManifest | null {
  const candidates = [
    join(packageRoot, 'dist', MANIFEST_FILENAME),
    join(packageRoot, MANIFEST_FILENAME),
  ];
  manifestSymlinkRejection = null;
  for (const manifestPath of candidates) {
    // lstat (NOT stat) so we see the link itself, not its target. A broken
    // symlink (target missing) still trips this branch — existsSync follows
    // links and returns false on broken links, so we must lstat first.
    let stat: ReturnType<typeof lstatSync> | null = null;
    try {
      stat = lstatSync(manifestPath);
    } catch (err) {
      // ENOENT and friends: nothing at this path. Try the next candidate.
      // Any other error (EACCES, etc.) we also skip — manifest unavailable
      // here, but we don't want to crash the verifier on permission errors;
      // the next candidate or the null return will surface dev-mode.
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') continue;
      // Surface non-ENOENT errors to stderr so they're not silently swallowed
      // (per feedback_iife_after_parseasync_timing_trap.md — bare catch{} is
      // the silent-no-op mechanism we explicitly avoid).
      process.stderr.write(
        `INTEGRITY MANIFEST READ ERROR at ${escapePathForDisplay(manifestPath)}: ${escapeForDisplay((err as Error).message)}\n`,
      );
      continue;
    }
    if (stat.isSymbolicLink()) {
      process.stderr.write(
        `INTEGRITY MANIFEST REJECTED: symlink at ${escapePathForDisplay(manifestPath)} (manifests must be regular files)\n`,
      );
      manifestSymlinkRejection = manifestPath;
      continue;
    }
    if (!stat.isFile()) {
      // Not a regular file (could be a directory, socket, fifo, etc.)
      process.stderr.write(
        `INTEGRITY MANIFEST REJECTED: not a regular file at ${escapePathForDisplay(manifestPath)}\n`,
      );
      continue;
    }
    try {
      const raw = readFileSync(manifestPath, 'utf-8');
      return JSON.parse(raw) as IntegrityManifest;
    } catch (err) {
      // Surface the parse / read failure so a malformed manifest doesn't
      // silently downgrade to dev-mode.
      process.stderr.write(
        `INTEGRITY MANIFEST PARSE ERROR at ${escapePathForDisplay(manifestPath)}: ${escapeForDisplay((err as Error).message)}\n`,
      );
      continue;
    }
  }
  return null;
}

/** Module-scoped flag so verifyAll can report manifest-rejected-by-symlink. */
let manifestSymlinkRejection: string | null = null;

/**
 * Generate a manifest from the current state of dist/ files.
 * Used during build/publish to create the signed manifest.
 */
export function generateManifest(
  packageRoot: string,
  signingKey?: string,
): IntegrityManifest {
  const pkgJsonPath = join(packageRoot, 'package.json');
  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf-8'));
  const distDir = join(packageRoot, 'dist');
  const files: Record<string, string> = {};

  if (existsSync(distDir)) {
    collectFileHashes(distDir, distDir, files);
  }

  const manifest: IntegrityManifest = {
    version: pkgJson.version as string,
    files,
  };

  // Add model hash if model exists
  if (existsSync(MODELS_DIR)) {
    const modelFiles = readdirSync(MODELS_DIR).filter(f => f.endsWith('.gguf'));
    if (modelFiles.length > 0) {
      manifest.modelHash = sha256File(join(MODELS_DIR, modelFiles[0]));
    }
  }

  // Sign if key provided
  if (signingKey) {
    const payload = canonicalManifestPayload(manifest);
    manifest.signature = hmacSign(payload, signingKey);
  }

  return manifest;
}

function collectFileHashes(
  baseDir: string,
  currentDir: string,
  out: Record<string, string>,
): void {
  const entries = readdirSync(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(currentDir, entry.name);
    if (entry.isDirectory()) {
      collectFileHashes(baseDir, fullPath, out);
    } else if (entry.isFile()) {
      const relative = fullPath.slice(baseDir.length + 1);
      // Skip the manifest itself: it can't reference its own post-write
      // hash (chicken-and-egg). On re-builds this would put a fresh
      // install into permanent QUARANTINE because the stored hash from
      // the previous build never matches the freshly-written manifest.
      if (relative === MANIFEST_FILENAME) continue;
      out[relative] = sha256File(fullPath);
    }
  }
}

function canonicalManifestPayload(manifest: IntegrityManifest): string {
  // Exclude the signature field itself from the payload
  const { signature: _, ...rest } = manifest;
  return JSON.stringify(rest, Object.keys(rest).sort());
}

// ============================================================================
// Tamper-Evident Event Chain
// ============================================================================

export class EventChain {
  private chainPath: string;

  constructor(chainPath: string = EVENT_CHAIN_PATH) {
    this.chainPath = chainPath;
  }

  /**
   * Append an event to the chain. Each event references the hash of the
   * previous event, forming a tamper-evident linked chain.
   */
  append(eventType: TamperEvent['eventType'], detail: string): TamperEvent {
    const lastEvent = this.getLastEvent();
    const prevHash = lastEvent
      ? sha256(JSON.stringify(lastEvent))
      : GENESIS_PREV_HASH;

    const event: TamperEvent = {
      seq: lastEvent ? lastEvent.seq + 1 : 0,
      timestamp: new Date().toISOString(),
      eventType,
      detail,
      prevHash,
    };

    const dir = dirname(this.chainPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    appendFileSync(this.chainPath, JSON.stringify(event) + '\n', 'utf-8');
    return event;
  }

  /**
   * Read all events from the chain file.
   */
  readAll(): TamperEvent[] {
    if (!existsSync(this.chainPath)) return [];
    const raw = readFileSync(this.chainPath, 'utf-8').trim();
    if (!raw) return [];
    return raw.split('\n').map(line => JSON.parse(line) as TamperEvent);
  }

  /**
   * Get the last event in the chain.
   */
  getLastEvent(): TamperEvent | null {
    const events = this.readAll();
    return events.length > 0 ? events[events.length - 1] : null;
  }

  /**
   * Verify the entire chain is intact. Returns the index of the first
   * broken link, or -1 if the chain is valid.
   *
   * Detects:
   *   - Modified events (prevHash mismatch)
   *   - Truncated chains (missing events break the link)
   *   - Inserted events (sequence number gaps or hash mismatches)
   */
  verify(): { valid: boolean; brokenAt: number; reason?: string } {
    const events = this.readAll();
    if (events.length === 0) {
      return { valid: true, brokenAt: -1 };
    }

    // Genesis event must reference the zero hash
    if (events[0].prevHash !== GENESIS_PREV_HASH) {
      return { valid: false, brokenAt: 0, reason: 'Genesis event has wrong prevHash' };
    }

    if (events[0].seq !== 0) {
      return { valid: false, brokenAt: 0, reason: 'Genesis event has wrong sequence number' };
    }

    for (let i = 1; i < events.length; i++) {
      const expectedPrevHash = sha256(JSON.stringify(events[i - 1]));
      if (events[i].prevHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenAt: i,
          reason: `Event ${i}: prevHash mismatch (expected ${expectedPrevHash.slice(0, 16)}..., got ${events[i].prevHash.slice(0, 16)}...)`,
        };
      }
      if (events[i].seq !== i) {
        return {
          valid: false,
          brokenAt: i,
          reason: `Event ${i}: sequence number mismatch (expected ${i}, got ${events[i].seq})`,
        };
      }
    }

    return { valid: true, brokenAt: -1 };
  }
}

// ============================================================================
// Individual Integrity Checks
// ============================================================================

/**
 * Verify package dist/ files against the manifest.
 * If any file hash differs, the package has been tampered with.
 */
export function checkPackageIntegrity(
  packageRoot: string,
  manifest: IntegrityManifest,
): IntegrityCheck {
  const distDir = join(packageRoot, 'dist');

  if (!existsSync(distDir)) {
    return { name: 'package_integrity', passed: false, reason: 'dist/ directory missing' };
  }

  // Verify version matches
  const pkgJsonPath = join(packageRoot, 'package.json');
  if (existsSync(pkgJsonPath)) {
    try {
      const pkgJson = JSON.parse(readFileSync(pkgJsonPath, 'utf-8'));
      if (pkgJson.version !== manifest.version) {
        return {
          name: 'package_integrity',
          passed: false,
          reason: `Version mismatch: package.json=${pkgJson.version}, manifest=${manifest.version}`,
        };
      }
    } catch {
      return { name: 'package_integrity', passed: false, reason: 'Failed to read package.json' };
    }
  }

  // Verify file hashes. Missing files short-circuit (a missing file can
  // hide further tamper — operators need to know about it first), but
  // hash mismatches accumulate so multi-file tamper is fully reported.
  const tamperedFiles: string[] = [];
  for (const [relativePath, expectedHash] of Object.entries(manifest.files)) {
    const fullPath = join(distDir, relativePath);
    if (!existsSync(fullPath)) {
      return {
        name: 'package_integrity',
        passed: false,
        reason: `Missing file: dist/${relativePath}`,
      };
    }
    const actualHash = sha256File(fullPath);
    if (actualHash !== expectedHash) {
      tamperedFiles.push(relativePath);
    }
  }

  if (tamperedFiles.length > 0) {
    return {
      name: 'package_integrity',
      passed: false,
      reason: formatTamperedFilesReason(tamperedFiles),
    };
  }

  return { name: 'package_integrity', passed: true };
}

/**
 * Format the multi-file tamper reason. Reports total count + first 5 paths
 * in lexicographic order. Caps total output at 200 chars to defeat attacker
 * log-flooding (an attacker who tampers thousands of files cannot blow up
 * downstream log pipelines by producing megabyte-scale stderr).
 *
 * Default Array.prototype.sort() comparator is locale-independent on
 * strings — compares 16-bit code units — so the displayed order is stable
 * across Node versions and locales.
 */
function formatTamperedFilesReason(tamperedFiles: string[]): string {
  const sorted = [...tamperedFiles].sort();
  const count = sorted.length;
  const first5 = sorted.slice(0, 5);
  const moreSuffix = count > 5 ? `, ...and ${count - 5} more` : '';
  let reason = `${count} files tampered: ${first5.join(', ')}${moreSuffix}`;
  // Hard cap at 200 chars. If we exceed, truncate the file list and append
  // a count-only suffix so the operator still sees the total.
  const HARD_CAP = 200;
  if (reason.length > HARD_CAP) {
    // Drop paths from the end until we fit. Keep at least the count + 1
    // path so the reason remains informative.
    const minPrefix = `${count} files tampered: `;
    const minSuffix = `, ...and ${count - 1} more`;
    const budget = HARD_CAP - minPrefix.length - minSuffix.length;
    if (budget <= 0) {
      reason = `${minPrefix.slice(0, HARD_CAP - 3)}...`.slice(0, HARD_CAP);
    } else {
      const oneTruncated = first5[0].length > budget
        ? first5[0].slice(0, budget - 3) + '...'
        : first5[0];
      reason = `${minPrefix}${oneTruncated}${minSuffix}`.slice(0, HARD_CAP);
    }
  }
  return reason;
}

/**
 * Verify NanoMind GGUF model file hash BEFORE loading.
 * If the model does not exist, the check passes (model is optional).
 * If the model exists but hash differs, return failure (DEGRADE mode).
 */
export function checkModelIntegrity(manifest: IntegrityManifest): IntegrityCheck {
  if (!manifest.modelHash) {
    return { name: 'model_integrity', passed: true, reason: 'No model hash in manifest (model optional)' };
  }

  if (!existsSync(MODELS_DIR)) {
    return { name: 'model_integrity', passed: true, reason: 'No models directory (model optional)' };
  }

  const modelFiles = readdirSync(MODELS_DIR).filter(f => f.endsWith('.gguf'));
  if (modelFiles.length === 0) {
    return { name: 'model_integrity', passed: true, reason: 'No model files found (model optional)' };
  }

  const modelPath = join(MODELS_DIR, modelFiles[0]);
  const actualHash = sha256File(modelPath);
  if (actualHash !== manifest.modelHash) {
    return {
      name: 'model_integrity',
      passed: false,
      reason: `Model hash mismatch: expected ${manifest.modelHash.slice(0, 16)}..., got ${actualHash.slice(0, 16)}...`,
    };
  }

  return { name: 'model_integrity', passed: true };
}

/**
 * Verify rule manifest integrity.
 * If the manifest specifies a rule category count, verify it matches.
 */
export function checkRuleManifest(manifest: IntegrityManifest): IntegrityCheck {
  if (manifest.ruleCategories === undefined) {
    return { name: 'rule_manifest', passed: true, reason: 'No rule category count in manifest' };
  }

  // Count actual rule categories from the scanner rules directory
  // This is a fast check: just count directories in the rules path
  const rulesDir = join(dirname(dirname(__dirname)), 'rules');
  if (!existsSync(rulesDir)) {
    // In dist/ the rules may not exist as a directory, accept the count from manifest
    return { name: 'rule_manifest', passed: true, reason: 'Rules directory not found (packaged mode)' };
  }

  try {
    const categories = readdirSync(rulesDir, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .length;
    if (categories !== manifest.ruleCategories) {
      return {
        name: 'rule_manifest',
        passed: false,
        reason: `Rule category count mismatch: expected ${manifest.ruleCategories}, got ${categories}`,
      };
    }
  } catch {
    return { name: 'rule_manifest', passed: true, reason: 'Could not enumerate rules (non-critical)' };
  }

  return { name: 'rule_manifest', passed: true };
}

/**
 * Verify manifest signature using HMAC-SHA256 (Ed25519 fallback).
 * If no signing key is available, this check is skipped.
 */
export function checkManifestSignature(
  manifest: IntegrityManifest,
  signingKey?: string,
): IntegrityCheck {
  if (!manifest.signature) {
    return { name: 'manifest_signature', passed: true, reason: 'No signature in manifest (unsigned)' };
  }

  if (!signingKey) {
    return { name: 'manifest_signature', passed: true, reason: 'No signing key available (skipped)' };
  }

  const payload = canonicalManifestPayload(manifest);
  const valid = hmacVerify(payload, signingKey, manifest.signature);

  if (!valid) {
    return {
      name: 'manifest_signature',
      passed: false,
      reason: 'Manifest signature verification failed',
    };
  }

  return { name: 'manifest_signature', passed: true };
}

// ============================================================================
// Main Entry Point
// ============================================================================

export interface VerifyOptions {
  /** Package root directory (defaults to resolved from this module) */
  packageRoot?: string;
  /** HMAC signing key for manifest signature verification */
  signingKey?: string;
  /** Path to event chain file (defaults to ~/.nanomind/integrity-events.jsonl) */
  eventChainPath?: string;
  /** Custom manifest (for testing) */
  manifest?: IntegrityManifest;
}

/**
 * Run all startup integrity checks. Must complete in < 5ms for clean installations.
 *
 * Returns:
 *   CLEAN      -- All checks passed
 *   DEGRADE    -- Model integrity failed (heuristic fallback)
 *   QUARANTINE -- Package integrity failed (refuse to output, exit code 3)
 */
export function verifyAll(options: VerifyOptions = {}): IntegrityResult {
  const start = performance.now();

  const packageRoot = options.packageRoot ?? resolvePackageRoot();
  const eventChain = new EventChain(options.eventChainPath);
  const checks: IntegrityCheck[] = [];

  // Load manifest
  const manifest = options.manifest ?? loadManifest(packageRoot);

  if (!manifest) {
    // No manifest = development mode or first install. Pass all checks.
    // If loadManifest rejected a symlink, surface the explicit reason so
    // ops/forensics can distinguish "no manifest" from "manifest tampered".
    // The synchronous call ordering (loadManifest → flag read → flag clear)
    // ensures no race even if another caller is running in the same worker.
    const duration = performance.now() - start;
    const rejectedSymlink = manifestSymlinkRejection;
    manifestSymlinkRejection = null; // capture-and-clear: no stale state
    const reason = rejectedSymlink
      ? 'Manifest rejected (symlink) — dev mode'
      : 'No manifest found (dev mode)';
    checks.push({ name: 'manifest_load', passed: true, reason });
    const detail = rejectedSymlink
      ? `Integrity check: manifest rejected (symlink at ${rejectedSymlink}) (${duration.toFixed(2)}ms)`
      : `Integrity check: no manifest, dev mode (${duration.toFixed(2)}ms)`;
    eventChain.append('startup', detail);
    return { status: 'CLEAN', checks, durationMs: duration };
  }

  // Run checks in order of severity (most severe first for early determination)

  // 1. Package/dist integrity (QUARANTINE if failed)
  const pkgCheck = checkPackageIntegrity(packageRoot, manifest);
  checks.push(pkgCheck);

  // 2. Manifest signature
  const sigCheck = checkManifestSignature(manifest, options.signingKey);
  checks.push(sigCheck);

  // 3. Model integrity (DEGRADE if failed)
  const modelCheck = checkModelIntegrity(manifest);
  checks.push(modelCheck);

  // 4. Rule manifest
  const ruleCheck = checkRuleManifest(manifest);
  checks.push(ruleCheck);

  // Determine status
  let status: IntegrityStatus = 'CLEAN';

  // QUARANTINE: package tampered or signature invalid
  if (!pkgCheck.passed || !sigCheck.passed) {
    status = 'QUARANTINE';
  }
  // DEGRADE: model tampered (but package is fine)
  else if (!modelCheck.passed) {
    status = 'DEGRADE';
  }
  // Rule manifest failure is a soft degrade
  else if (!ruleCheck.passed) {
    status = 'DEGRADE';
  }

  const duration = performance.now() - start;

  // Log to event chain
  const eventType = status === 'CLEAN' ? 'check_pass'
    : status === 'DEGRADE' ? 'degraded'
    : 'quarantine';
  const failedChecks = checks.filter(c => !c.passed).map(c => c.name).join(', ');
  const detail = status === 'CLEAN'
    ? `All ${checks.length} checks passed (${duration.toFixed(2)}ms)`
    : `Status=${status}, failed=[${failedChecks}] (${duration.toFixed(2)}ms)`;
  eventChain.append(eventType, detail);

  return { status, checks, durationMs: duration };
}

/**
 * Resolve the package root by walking up from this file to find package.json.
 */
function resolvePackageRoot(): string {
  let dir = __dirname;
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, 'package.json'))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}
