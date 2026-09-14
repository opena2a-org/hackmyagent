'use strict';
// Two CONCURRENT scans of disjoint roots in ONE process, through the BUILT
// `HardeningScanner.scan`, printing one JSON line the HMA-26 suite reads:
//
//   node --require fs-reach-recorder.cjs __tests__/helpers/concurrent-scan-driver.cjs <dirA> <dirB>
//
// The module-global ledger defect is per-process, so `scan-driver.cjs` (one
// scan per process) cannot exhibit it: this driver runs the two scans under
// `Promise.all`, then runs the same two scans sequentially as the control.
// It reports each scan's withheld links for both phases; the reach recorder
// preloaded around it (confined to both roots) records every link-following
// call that got past the guard. On the base extract the concurrent phase
// leaks — each scan consults the OTHER scan's ledger, whose roots do not
// cover its paths — while the sequential control stays clean.

const path = require('node:path');
const DIST = path.resolve(__dirname, '../../dist');
const { HardeningScanner } = require(path.join(DIST, 'hardening/scanner.js'));

const [dirA, dirB] = process.argv.slice(2);

const scan = (dir) => new HardeningScanner().scan({
  targetDir: dir, autoFix: false, dryRun: false, ignore: [], deep: false,
  scanDepth: 'standard', cliName: 'hackmyagent',
});

const links = (result) => (result.withheldLinks || [])
  .map((w) => ({ rel: w.rel, resolved: w.resolved }))
  .sort((a, b) => a.rel.localeCompare(b.rel));

(async () => {
  const [conA, conB] = await Promise.all([scan(dirA), scan(dirB)]);
  const seqA = await scan(dirA);
  const seqB = await scan(dirB);
  process.stdout.write(JSON.stringify({
    concurrent: { a: links(conA), b: links(conB) },
    sequential: { a: links(seqA), b: links(seqB) },
  }) + '\n');
})().catch((e) => {
  process.stderr.write('DRIVER ERROR ' + (e && e.stack || e) + '\n');
  process.exit(9);
});
