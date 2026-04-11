/**
 * ML-DSA-44 sign p99 microbenchmark (AC-016).
 *
 * Budget: p99 under 2ms on the reference dev laptop (MacBook Pro M4 Max).
 * This runs inside the regular vitest suite so every commit measures it, but
 * the assertion uses a generous ceiling so CI on slower runners does not
 * flake. If you see this test failing on the dev laptop, investigate the
 * regression before committing.
 *
 * The benchmark uses `performance.now()` with 1000 iterations after a 50-call
 * warmup to amortize the first-call cost (module init, JIT warmup).
 *
 * ML-DSA-44 was chosen because it is the hot path: `verifyClassification()`
 * runs on every NanoMind-Guard result and the p99 budget there is tight.
 * ML-DSA-65 and ML-DSA-87 sign less frequently (manifest loads, root key ops)
 * and have correspondingly looser budgets not enforced here.
 */

import { describe, it, expect } from 'vitest';
import { generateHybridKeyPair } from './index';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa';

const WARMUP_ITERS = 50;
const MEASURE_ITERS = 1000;

// The ceiling is deliberately loose compared to the 2ms dev laptop target so
// this test does not flake on slower CI runners. The real p99 budget lives
// in the review checklist for AIComply P1; this test catches only large
// regressions (order of magnitude slowdowns) automatically.
const CEILING_MS = 20;

function percentile(samples: number[], p: number): number {
  const sorted = [...samples].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(p * sorted.length));
  return sorted[idx];
}

describe('arp/crypto ML-DSA-44 sign p99 benchmark', () => {
  it(`sign p99 stays under ${CEILING_MS}ms over ${MEASURE_ITERS} iterations`, async () => {
    const keys = await generateHybridKeyPair('ML-DSA-44');
    const payload = new TextEncoder().encode(
      'nanomind-guard classification benchmark payload',
    );

    // Warmup: run the primitive enough times to let V8 inline it.
    for (let i = 0; i < WARMUP_ITERS; i++) {
      ml_dsa44.sign(keys.mldsa.privateKey, payload);
    }

    const samples: number[] = new Array(MEASURE_ITERS);
    for (let i = 0; i < MEASURE_ITERS; i++) {
      const start = performance.now();
      ml_dsa44.sign(keys.mldsa.privateKey, payload);
      samples[i] = performance.now() - start;
    }

    const p50 = percentile(samples, 0.5);
    const p99 = percentile(samples, 0.99);
    const max = Math.max(...samples);

    // Log the observed numbers so the human reviewer can spot drift against
    // the 2ms dev laptop target even when the loose CI ceiling passes.
    // eslint-disable-next-line no-console
    console.log(
      `[arp/crypto] ML-DSA-44 sign: p50=${p50.toFixed(3)}ms p99=${p99.toFixed(3)}ms max=${max.toFixed(3)}ms over ${MEASURE_ITERS} iters`,
    );

    expect(p99).toBeLessThan(CEILING_MS);
  });
});
