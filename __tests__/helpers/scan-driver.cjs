'use strict';
// In-process scan of one directory through the BUILT `HardeningScanner.scan`,
// printing one JSON line the confinement suite reads:
//
//   node [--require fs-reach-recorder.cjs] __tests__/helpers/scan-driver.cjs <dir> [<confineRoot>...]
//
// Reports the settled exit, score, failing check IDs, unread-input count, the
// withheld links, and how many times $HMA_TEST_CANARY appears in the
// serialized result and in the Layer-3 input (`discoverFiles` run under the
// scan's ledger, exactly as the scanner runs it). Runs against `dist`, so the
// same driver measures the pre-fix extract and the fixed tree.

const path = require('node:path');
const DIST = path.resolve(__dirname, '../../dist');
const { HardeningScanner } = require(path.join(DIST, 'hardening/scanner.js'));
const { settleSecureExit, unreadInputCount } = require(path.join(DIST, 'hardening/settled-outcome.js'));
const { CoverageLedger, withActiveLedger } = require(path.join(DIST, 'hardening/coverage-ledger.js'));
const { StructuralAnalyzer } = require(path.join(DIST, 'semantic/index.js'));

const [dir, ...roots] = process.argv.slice(2);
const CANARY = process.env.HMA_TEST_CANARY || '';
const count = (s) => (CANARY ? (s.match(new RegExp(CANARY, 'g')) || []).length : 0);

(async () => {
  const scanner = new HardeningScanner();
  const opts = { targetDir: dir, autoFix: false, dryRun: false, ignore: [], deep: false, scanDepth: 'standard', cliName: 'hackmyagent' };
  if (roots.length > 0) opts.confineRoots = roots;
  const result = await scanner.scan(opts);

  // The Layer-3 input as the scanner would build it: under a ledger for the
  // same target (the guard has no root set outside one).
  const ledger = new CoverageLedger(dir);
  if (roots.length > 0 && typeof ledger.setConfineRoots === 'function') ledger.setConfineRoots(roots);
  const files = await withActiveLedger(ledger, () => new StructuralAnalyzer().discoverFiles(dir, {}));

  const failing = (result.findings || []).filter((f) => f.passed === false).map((f) => f.checkId).sort();
  process.stdout.write(JSON.stringify({
    exit: settleSecureExit(result),
    score: result.score,
    failingCheckIds: failing,
    unread: unreadInputCount(result),
    withheldLinks: result.withheldLinks || [],
    canaryInResult: count(JSON.stringify(result)),
    canaryInLayer3Input: count(JSON.stringify(files)),
    layer3Paths: files.map((f) => f.path).sort(),
  }) + '\n');
})().catch((e) => {
  process.stderr.write('DRIVER ERROR ' + (e && e.stack || e) + '\n');
  process.exit(9);
});
