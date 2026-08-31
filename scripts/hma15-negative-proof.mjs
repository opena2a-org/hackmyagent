#!/usr/bin/env node
/**
 * HMA-15.AC6 — the negative proof: the property test can fail, and a NEW
 * producer is what fails it.
 *
 * The credential-byte render class was patched per-producer twice (v0.25.2,
 * v0.32.0) and survived both times, so a per-producer test is a REJECTED
 * design for this defect. The property test claims to be producer-agnostic;
 * this script proves the claim by construction:
 *
 *   1. copy `src/` into an OS temp scratch tree (this working tree is never
 *      touched, and nothing here is ever committed);
 *   2. add a DELIBERATE fourth producer to the scratch copy — a site that
 *      copies raw scanned content into a finding field, modeling the exact
 *      anchor-cut truncation shape of the three historical leaks (it slices
 *      the tail of each long line, so a name-gated value crosses the report
 *      boundary without its anchor and no shape rule can remove it);
 *   3. build the scratch tree;
 *   4. run the UNMODIFIED committed property test against that build via the
 *      HMA15_CLI override, and require it to go RED;
 *   5. record the red run — mutated build identity (path + sha256), vitest
 *      exit code, and the run-artifact path — as the AC6 evidence artifact.
 *
 * The test file is not edited, the mutation names no test, and the property
 * test knows nothing about the producer added here. If the matrix stays
 * green over the mutation, THIS SCRIPT exits non-zero: a property test that
 * cannot see a new producer copying raw bytes is not holding the class
 * closed.
 *
 * Value hygiene (HMA-15.AC7) holds transitively: the planted values live
 * inside the vitest child, whose failure messages come from the harness
 * formatter that is itself pinned to emit no value bytes.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const scratch = mkdtempSync(join(tmpdir(), 'hma15-negproof-'));

const MUTATION_ANCHOR = `  findings.push(...checkHardcodedSecrets(ast, artifactContent));

  return findings;`;

const MUTATION = `  findings.push(...checkHardcodedSecrets(ast, artifactContent));

  // HMA-15.AC6 NEGATIVE-PROOF MUTATION (never committed to a shipping tree):
  // a fourth producer that copies raw scanned content into a finding field.
  // The tail slice cuts any name anchor off, so the report boundary's
  // name-gated shape rule cannot match what ships — the historical leak
  // shape, reintroduced at a site no per-producer test names.
  if (artifactContent !== undefined && findings.length > 0) {
    const rawTails = artifactContent
      .split('\\n')
      .filter((l) => l.length >= 48)
      .map((l) => l.slice(-44));
    if (rawTails.length > 0) {
      findings[0].message = findings[0].message + ' ctx: ' + rawTails.join(' | ');
    }
  }

  return findings;`;

function step(name, fn) {
  process.stdout.write(`hma15-negative-proof: ${name}\n`);
  return fn();
}

/** Stable whole-tree hash: sorted relative paths, each with its file sha256. */
function sha256Tree(dir) {
  const files = [];
  const walk = (rel) => {
    for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
      const relPath = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(relPath);
      else if (entry.isFile()) files.push(relPath);
    }
  };
  walk('');
  files.sort();
  const hash = createHash('sha256');
  for (const relPath of files) {
    hash.update(relPath);
    hash.update('\0');
    hash.update(createHash('sha256').update(readFileSync(join(dir, relPath))).digest('hex'));
    hash.update('\n');
  }
  return hash.digest('hex');
}

try {
  step('copying src into scratch tree', () => {
    cpSync(join(repoRoot, 'src'), join(scratch, 'src'), { recursive: true });
    cpSync(join(repoRoot, 'tsconfig.json'), join(scratch, 'tsconfig.json'));
    cpSync(join(repoRoot, 'package.json'), join(scratch, 'package.json'));
    symlinkSync(join(repoRoot, 'node_modules'), join(scratch, 'node_modules'), 'dir');
  });

  step('adding the fourth producer', () => {
    const target = join(scratch, 'src', 'nanomind-core', 'analyzers', 'credential-analyzer.ts');
    const source = readFileSync(target, 'utf8');
    if (!source.includes(MUTATION_ANCHOR)) {
      throw new Error('mutation anchor not found — re-pin the anchor against the current analyzer source');
    }
    writeFileSync(target, source.replace(MUTATION_ANCHOR, MUTATION), 'utf8');
  });

  step('building the mutated tree', () => {
    const tsc = spawnSync(
      'node',
      [join(repoRoot, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', '.'],
      { cwd: scratch, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
    );
    if (tsc.status !== 0) {
      throw new Error(`tsc failed on the mutated tree:\n${tsc.stdout}\n${tsc.stderr}`);
    }
    // Mirror the integrity-manifest half of `npm run build`, so the mutated
    // CLI runs exactly as a real build would.
    const manifest = spawnSync(
      'node',
      [
        '-e',
        "const{generateManifest}=require('./dist/nanomind-core/security/integrity-verifier.js');const m=generateManifest(__dirname);if(m)require('fs').writeFileSync('dist/.integrity-manifest.json',JSON.stringify(m))",
      ],
      { cwd: scratch, encoding: 'utf8' },
    );
    if (manifest.status !== 0) {
      throw new Error(`integrity manifest generation failed:\n${manifest.stderr}`);
    }
  });

  const mutatedCli = join(scratch, 'dist', 'cli.js');
  if (!existsSync(mutatedCli)) throw new Error('mutated build produced no dist/cli.js');
  const mutatedSha = createHash('sha256').update(readFileSync(mutatedCli)).digest('hex');
  // AC10 r2: cli.js hashes IDENTICAL across builds that differ only in the
  // analyzers (this mutation never touches src/cli.ts), so the identity that
  // distinguishes the mutated build is the whole dist tree.
  const mutatedDistSha = sha256Tree(join(scratch, 'dist'));

  const evidenceDir = process.env.HMA15_NEGATIVE_PROOF_DIR ?? mkdtempSync(join(tmpdir(), 'hma15-negproof-evidence-'));
  const runArtifact = join(evidenceDir, 'mutated-property-run.json');

  const vitestExit = step('running the UNMODIFIED property test against the mutated build', () => {
    const env = { ...process.env, HMA15_CLI: mutatedCli, HMA15_RUN_ARTIFACT: runArtifact };
    // The property suite NEVER skips (HMA-15.AC11) — the r1 CI-marker guard
    // is gone — so nothing here depends on the environment. The markers are
    // still cleared as plain hygiene: this proof measures the mutated BUILD,
    // not whatever CI decoration the caller's shell carries.
    delete env.CI;
    delete env.GITHUB_ACTIONS;
    const vitestEntry = join(repoRoot, 'node_modules', 'vitest', 'vitest.mjs');
    const runner = existsSync(vitestEntry)
      ? ['node', [vitestEntry]]
      : [join(repoRoot, 'node_modules', '.bin', 'vitest'), []];
    const vitest = spawnSync(
      runner[0],
      [...runner[1], 'run', '__tests__/cli/hma15-credential-render-property.test.ts'],
      { cwd: repoRoot, encoding: 'utf8', env, maxBuffer: 64 * 1024 * 1024 },
    );
    process.stdout.write(vitest.stdout ?? '');
    process.stderr.write(vitest.stderr ?? '');
    return vitest.status;
  });

  const red = vitestExit !== 0 && vitestExit !== null;
  const proof = {
    task: 'HMA-15',
    criterion: 'HMA-15.AC6',
    mutation:
      'fourth producer in analyzeCredentials: appends anchor-cut raw line tails of the scanned artifact to a finding message',
    mutatedCli: { path: mutatedCli, sha256: mutatedSha, distTreeSha256: mutatedDistSha },
    vitestExitCode: vitestExit,
    propertyTestWentRed: red,
    runArtifact,
    recordedAt: new Date().toISOString(),
  };
  const proofPath = join(evidenceDir, 'negative-proof.json');
  writeFileSync(proofPath, JSON.stringify(proof, null, 2) + '\n', 'utf8');
  process.stdout.write(`hma15-negative-proof: evidence at ${proofPath}\n`);

  if (!red) {
    process.stderr.write(
      'hma15-negative-proof: FAILURE — the property test stayed GREEN over a producer that copies raw scanned content. The property is not holding the class closed.\n',
    );
    // exitCode rather than process.exit(): an immediate exit would skip the
    // finally-block cleanup of the scratch tree.
    process.exitCode = 1;
  } else {
    process.stdout.write('hma15-negative-proof: OK — the unmodified property test went RED over the added producer.\n');
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
