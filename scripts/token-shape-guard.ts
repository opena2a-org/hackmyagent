/**
 * Hand-runnable entry point for the provider-token-shape guard (HMA-16).
 *
 *   npm run guard:token-shapes
 *
 * This is a convenience wrapper only: the enforcing copy is
 * `__tests__/hardening/token-shape-guard.test.ts`, which `npm test` (and so
 * `.github/workflows/test-matrix.yml`) runs on every push and PR. Exits 0
 * when every matching line resolves to a registry entry, 1 otherwise. Prints
 * paths and line numbers only — never matched text.
 */
import {
  loadRegistry,
  scanRepository,
  formatViolations,
} from '../__tests__/helpers/token-shape-guard';

const root = process.cwd();
const result = scanRepository(root, loadRegistry(root));

console.log(`token-shape guard: ${result.matchedLineCount} matching line(s), ${result.unregisteredLineCount} unregistered`);
for (const line of formatViolations(result)) console.error(line);
console.log(result.ok ? 'PASS' : 'FAIL');
process.exit(result.ok ? 0 : 1);
