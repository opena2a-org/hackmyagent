/**
 * Benchmarks module
 * OASB (OpenA2A Security Benchmark) implementations
 */

export {
  OASB_1_CATEGORIES,
  OASB_1_VERSION,
  OASB_1_NAME,
  getControlsForLevel,
  getControlsForCategory,
  getCheckIdsForLevel,
  calculateRating,
} from './oasb-1';

export type {
  BenchmarkLevel,
  BenchmarkControl,
  BenchmarkCategory,
  BenchmarkResult,
  BenchmarkCategoryResult,
  BenchmarkControlResult,
} from './oasb-1';

/**
 * Available benchmarks
 */
export const AVAILABLE_BENCHMARKS = ['oasb-1'] as const;
export type BenchmarkName = (typeof AVAILABLE_BENCHMARKS)[number];

/**
 * Validate benchmark name
 */
export function isValidBenchmark(name: string): name is BenchmarkName {
  return AVAILABLE_BENCHMARKS.includes(name as BenchmarkName);
}
