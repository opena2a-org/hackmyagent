/**
 * The `Deps` line of `check`'s registry block.
 *
 * `check express` printed `Deps      0 total · min trust 2/4`: the block
 * beside a local scan printed the line whenever the registry record carried
 * a `dependencies` object, so a count of zero and a minimum trust level taken
 * over those zero dependencies printed together. The registry-only block
 * already omitted the line at zero. Both now take the value from one helper,
 * which omits the line unless the record counts at least one dependency.
 *
 * Two layers:
 * 1. The helper's contract.
 * 2. Lock-in over src/cli.ts: both render sites call the helper and neither
 *    builds the `total` segment itself.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { formatRegistryDeps } from '../../src/check/registry-deps';

describe('formatRegistryDeps', () => {
  it('omits the line when the record counts zero dependencies, whatever min trust says', () => {
    expect(formatRegistryDeps({ totalDeps: 0, minTrustLevel: 2 })).toBeNull();
    expect(formatRegistryDeps({ totalDeps: 0, vulnerableDeps: 0, minTrustLevel: 2 })).toBeNull();
  });

  it('omits the line when the record has no dependency count', () => {
    expect(formatRegistryDeps(undefined)).toBeNull();
    expect(formatRegistryDeps({})).toBeNull();
    expect(formatRegistryDeps({ minTrustLevel: 2 })).toBeNull();
    expect(formatRegistryDeps({ vulnerableDeps: 3, minTrustLevel: 1 })).toBeNull();
  });

  it('omits the line for a count that is not above zero', () => {
    expect(formatRegistryDeps({ totalDeps: -1, minTrustLevel: 2 })).toBeNull();
    expect(formatRegistryDeps({ totalDeps: Number.NaN, minTrustLevel: 2 })).toBeNull();
  });

  it('prints the count and min trust when the record counts dependencies', () => {
    expect(formatRegistryDeps({ totalDeps: 28, minTrustLevel: 2 })).toBe('28 total · min trust 2/4');
    expect(formatRegistryDeps({ totalDeps: 28 })).toBe('28 total');
  });

  it('names vulnerable dependencies only when there are some', () => {
    expect(formatRegistryDeps({ totalDeps: 28, vulnerableDeps: 0, minTrustLevel: 2 })).toBe('28 total · min trust 2/4');
    expect(formatRegistryDeps({ totalDeps: 28, vulnerableDeps: 3, minTrustLevel: 1 })).toBe('28 total · 3 vulnerable · min trust 1/4');
  });

  it('applies the caller style to the vulnerable segment and the separator', () => {
    const out = formatRegistryDeps(
      { totalDeps: 5, vulnerableDeps: 1, minTrustLevel: 3 },
      { vulnerable: (t) => `<r>${t}</r>`, separator: ' | ' },
    );
    expect(out).toBe('5 total | <r>1 vulnerable</r> | min trust 3/4');
  });
});

describe('check registry block: lock-in over src/cli.ts', () => {
  const source = readFileSync(join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');

  function bodyOf(signature: string): string {
    const start = source.indexOf(signature);
    expect(start, signature).toBeGreaterThan(-1);
    const end = source.indexOf('\n}\n', start);
    expect(end).toBeGreaterThan(start);
    return source.slice(start, end);
  }

  it('the registry-only block takes the Deps value from formatRegistryDeps', () => {
    expect(bodyOf('function renderRegistryOnlyCheck(')).toContain('formatRegistryDeps(registry.dependencies');
  });

  it('the block beside a local scan takes the Deps value from formatRegistryDeps', () => {
    expect(bodyOf('function displayUnifiedCheck(')).toContain('formatRegistryDeps(registry.dependencies');
  });

  it('no render site in src/cli.ts builds the `total` segment of the Deps line itself', () => {
    expect(source).not.toMatch(/\$\{d\.totalDeps\} total/);
  });
});
