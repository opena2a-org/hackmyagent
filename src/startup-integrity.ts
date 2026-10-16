/**
 * Startup integrity gate. src/cli.ts imports this module before anything
 * else, so the verifier runs before the rest of the CLI is loaded.
 *
 * The check used to run at the end of cli.ts, after its static imports had
 * resolved. Deleting a dist/ module that cli.ts imports (dist/explain-registry.js,
 * dist/attack/index.js) made module resolution throw first, and
 * `node dist/cli.js --version` exited 1 with a loader stack trace instead of
 * the QUARANTINE report and exit 3 (#1110). Here a QUARANTINE result stops the
 * load before any other dist/ module is required: the report is written, the
 * INTEGRITY_FAIL event is sent, and the process exits 3.
 *
 * Limit: dist/cli.js, this module, the verifier and the display-safe module
 * the verifier imports are loaded before the check runs, so deleting one of
 * them still fails at module resolution.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyAll, type IntegrityResult } from './nanomind-core/security/integrity-verifier';

/** The startup check's outcome, read by the entry function in cli.ts. */
export type StartupIntegrity = { result: IntegrityResult } | { error: unknown };

function runStartupCheck(): StartupIntegrity {
  try {
    return { result: verifyAll() };
  } catch (error) {
    // cli.ts reports this as "integrity check skipped" and continues.
    return { error };
  }
}

export const startupIntegrity: StartupIntegrity = runStartupCheck();

function writeQuarantineReport(integrity: IntegrityResult): void {
  // Binary tampered -- refuse to run
  process.stderr.write(
    '\nINTEGRITY CHECK FAILED: HackMyAgent binary may have been tampered with.\n' +
    'This could indicate a supply chain attack.\n\n' +
    'Actions:\n' +
    '  1. Reinstall: npm install -g hackmyagent\n' +
    '  2. Verify: npm audit signatures\n' +
    '  3. Report: https://github.com/opena2a-org/hackmyagent/security\n\n'
  );
  for (const check of integrity.checks.filter(c => !c.passed)) {
    process.stderr.write(`  Failed: ${check.name} -- ${check.reason}\n`);
  }
}

/** The version from the package's own package.json, as src/index.ts reads it. */
function packageVersion(): string {
  try {
    return JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8')).version;
  } catch {
    return 'unknown';
  }
}

/**
 * Supply-chain integrity violations get their own INTEGRITY_FAIL event row.
 * Loaded lazily so a quarantined run reads no more of the package than it has
 * to, and a missing module only costs the event, never the exit 3.
 */
async function sendIntegrityFailEvent(): Promise<void> {
  try {
    const tele = await import('@opena2a/telemetry');
    const { initWithAutomationOptOut } = await import('./telemetry/automation');
    await initWithAutomationOptOut(() => tele.init({ tool: 'hackmyagent', version: packageVersion() }));
    tele.error('startup', 'INTEGRITY_FAIL');
    // process.exit() does NOT trigger Node's beforeExit drain, so we flush
    // explicitly. tele.flush is bounded by the SDK's 2s per-event timeout.
    await tele.flush();
  } catch { /* never block integrity exit on a telemetry failure */ }
}

function exitQuarantined(): never {
  process.exit(3); // exit-no-event(pre-action/L001): fires and flushes its own INTEGRITY_FAIL event before exit. Exit code 3 = integrity failure.
}

if ('result' in startupIntegrity && startupIntegrity.result.status === 'QUARANTINE') {
  writeQuarantineReport(startupIntegrity.result);
  // Throwing is the one way to stop cli.js from requiring the rest of its
  // imports. The handler takes that throw (and anything uncaught after it),
  // sends the event and exits 3.
  let quarantineExit: Promise<void> | undefined;
  process.on('uncaughtException', () => {
    quarantineExit ??= sendIntegrityFailEvent().finally(exitQuarantined);
  });
  throw new Error('hackmyagent: integrity check failed, refusing to load the CLI');
}
