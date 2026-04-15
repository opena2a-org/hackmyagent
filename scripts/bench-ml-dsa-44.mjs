#!/usr/bin/env node
// ML-DSA-44 sign/verify p99 microbenchmark (AIComply AC-016).
//
// The ARP sign path is the hot loop: every NanoMind-Guard classification
// goes through one sign here. Budget per AIComply D17: sign p99 < 2.5ms on
// a production-class server (AWS c6i.xlarge or equivalent).
//
// Runs standalone (no test framework overhead) so CI numbers reflect the
// production path. Emits a parseable JSON summary on the last line.
//
// Usage: node scripts/bench-ml-dsa-44.mjs [--iters=1000] [--warmup=100]

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa';
import { performance } from 'node:perf_hooks';
import os from 'node:os';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [k, v] = a.replace(/^--/, '').split('=');
    return [k, v ?? true];
  }),
);

const ITERS = Number(args.iters ?? 1000);
const WARMUP = Number(args.warmup ?? 100);
const PAYLOAD = new TextEncoder().encode(
  'nanomind-guard classification benchmark payload',
);

// Budget enforced by AIComply AC-016 and D17.
const SIGN_P99_BUDGET_MS = 2.5;
const VERIFY_P99_BUDGET_MS = 1.5;

function percentile(samples, p) {
  const sorted = [...samples].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(p * sorted.length));
  return sorted[idx];
}

function bench(name, fn) {
  for (let i = 0; i < WARMUP; i++) fn();
  const samples = new Array(ITERS);
  for (let i = 0; i < ITERS; i++) {
    const t = performance.now();
    fn();
    samples[i] = performance.now() - t;
  }
  return {
    op: name,
    p50: percentile(samples, 0.5),
    p95: percentile(samples, 0.95),
    p99: percentile(samples, 0.99),
    max: Math.max(...samples),
    iters: ITERS,
  };
}

// Record the noble version so CI can detect drift against the budget baseline.
const here = dirname(fileURLToPath(import.meta.url));
const noblePkg = JSON.parse(
  readFileSync(join(here, '..', 'node_modules', '@noble', 'post-quantum', 'package.json'), 'utf8'),
);

const keys = ml_dsa44.keygen();
// noble 0.2.x API: sign(key, msg) — this is the hackmyagent production path.
// noble 0.6.x flipped to sign(msg, key); if hackmyagent ever bumps major, this
// line breaks and the drift guard in CI will catch it.
const sig = ml_dsa44.sign(keys.secretKey, PAYLOAD);

const signResult = bench('ml-dsa-44-sign', () =>
  ml_dsa44.sign(keys.secretKey, PAYLOAD),
);
const verifyResult = bench('ml-dsa-44-verify', () =>
  ml_dsa44.verify(keys.publicKey, PAYLOAD, sig),
);

const env = {
  platform: `${os.platform()}/${os.arch()}`,
  cpu: os.cpus()[0]?.model ?? 'unknown',
  cpuCount: os.cpus().length,
  node: process.version,
  totalMemGB: Math.round(os.totalmem() / 1024 / 1024 / 1024),
  nobleVersion: noblePkg.version,
  loadAvg: os.loadavg(),
};

const fmt = (r) =>
  `${r.op.padEnd(18)} p50=${r.p50.toFixed(3)}ms p95=${r.p95.toFixed(3)}ms p99=${r.p99.toFixed(3)}ms max=${r.max.toFixed(3)}ms`;

console.log(`env: ${env.platform} ${env.cpu} (${env.cpuCount} CPU) node=${env.node} noble=${env.nobleVersion}`);
console.log(`load avg: ${env.loadAvg.map((n) => n.toFixed(2)).join(', ')}`);
console.log(fmt(signResult));
console.log(fmt(verifyResult));

const signOver = signResult.p99 > SIGN_P99_BUDGET_MS;
const verifyOver = verifyResult.p99 > VERIFY_P99_BUDGET_MS;
console.log(
  `budget: sign p99 ${signOver ? 'OVER' : 'under'} ${SIGN_P99_BUDGET_MS}ms, verify p99 ${verifyOver ? 'OVER' : 'under'} ${VERIFY_P99_BUDGET_MS}ms`,
);

const summary = {
  env,
  budget: { sign: SIGN_P99_BUDGET_MS, verify: VERIFY_P99_BUDGET_MS },
  sign: signResult,
  verify: verifyResult,
  signOver,
  verifyOver,
};
console.log(`__BENCH_JSON__${JSON.stringify(summary)}`);

// Only hard-fail CI when explicitly requested. CI shared runners are noisy
// (load avg 2-5), so p99 can spike. The drift guard workflow compares results
// against the last recorded baseline and flags regressions, rather than failing
// on absolute budget every run.
if (signOver && process.env.BENCH_FAIL_ON_OVER === '1') {
  process.exit(1);
}
