/**
 * Lockstep equivalence test: hackmyagent's local CREDENTIAL_PATTERNS subset
 * must match @opena2a/credential-patterns@<pinned> byte-for-byte.
 *
 * hackmyagent's credvault catalog is a 10-entry subset of the canonical
 * 56-entry package catalog. This test asserts that for each local entry,
 * exactly one package entry has identical regex.source + regex.flags AND
 * the matched package entry's id equals the expected mapping below.
 *
 * Why this lives here (not in src/): credvault.ts must stay CJS-friendly
 * and synchronous to preserve zero-behavior-change in this PR. The package
 * is pure ESM and is imported via `await import()` in the test (vitest
 * runs ESM natively from a CJS source tree). credvault.ts itself does NOT
 * load the package at runtime — equivalence is asserted at CI time only.
 *
 * When the catalog deliberately broadens (e.g. credvault adopts the full
 * 56-pattern set), this test gets rewritten or replaced with an exact-equal
 * check. Until then, drift on either side fires it.
 */
import { describe, it, expect } from 'vitest';

import { CREDENTIAL_PATTERNS as LOCAL_PATTERNS } from '../../../src/plugins/credvault';

type PkgModule = typeof import('@opena2a/credential-patterns');

let pkgPromise: Promise<PkgModule> | null = null;
function loadPkg(): Promise<PkgModule> {
  if (!pkgPromise) pkgPromise = import('@opena2a/credential-patterns');
  return pkgPromise;
}

// Hardcoded mapping: local pattern name -> package id.
// Kept as data so a label drift on either side surfaces as a missing key,
// not a mysterious regex mismatch.
const LOCAL_NAME_TO_PKG_ID: Record<string, string> = {
  'Anthropic API Key': 'anthropic',
  'OpenAI API Key (project)': 'openai-proj',
  'OpenAI API Key (legacy)': 'openai-legacy',
  'AWS Access Key': 'aws-access',
  // hackmyagent's "GitHub Token (fine-grained)" label is misleading — the
  // regex /ghp_[a-zA-Z0-9]{36}/ is the classic personal access token, which
  // the canonical catalog calls 'github-pat'. Intentional.
  'GitHub Token (fine-grained)': 'github-pat',
  'GitHub PAT (new)': 'github-fine',
  'Slack Token': 'slack',
  'Google API Key': 'google',
  'Stripe Live Key': 'stripe',
  'SendGrid Key': 'sendgrid',
};

describe('lockstep: credvault CREDENTIAL_PATTERNS subset === @opena2a/credential-patterns', () => {
  it('mapping table covers every local pattern (no orphan local entries)', () => {
    const unmapped = LOCAL_PATTERNS
      .filter((p) => !(p.name in LOCAL_NAME_TO_PKG_ID))
      .map((p) => p.name);
    expect(unmapped, `Local patterns without a mapping entry:\n  ${unmapped.join('\n  ')}`).toEqual([]);
  });

  it('package catalog is at least as large as local subset', async () => {
    const pkg = await loadPkg();
    expect(pkg.CREDENTIAL_PATTERNS.length).toBeGreaterThanOrEqual(LOCAL_PATTERNS.length);
  });

  it('every local pattern matches exactly one package entry by regex.source + flags AND matches the expected package id', async () => {
    const pkg = await loadPkg();
    const drift: string[] = [];

    for (const local of LOCAL_PATTERNS) {
      const expectedId = LOCAL_NAME_TO_PKG_ID[local.name];
      if (!expectedId) {
        // covered by mapping-coverage test above, but double-check
        drift.push(`local=${local.name}: no expected package id in mapping`);
        continue;
      }

      const sourceMatches = pkg.CREDENTIAL_PATTERNS.filter(
        (r) => r.regex.source === local.regex.source && r.regex.flags === local.regex.flags,
      );

      if (sourceMatches.length === 0) {
        drift.push(
          `local=${local.name} (${local.regex.source} flags=${local.regex.flags || '(none)'}): no package entry with matching regex`,
        );
        continue;
      }
      if (sourceMatches.length > 1) {
        drift.push(
          `local=${local.name}: ${sourceMatches.length} package entries share this regex (${sourceMatches.map((m) => m.id).join(', ')}) — ordering rule violated`,
        );
        continue;
      }

      const matched = sourceMatches[0];
      if (matched.id !== expectedId) {
        drift.push(
          `local=${local.name}: regex matches package id=${matched.id} but mapping expects ${expectedId}`,
        );
      }
    }

    expect(drift, `Lockstep drift detected:\n  ${drift.join('\n  ')}`).toEqual([]);
  });

  it('each local regex source string is non-empty and parseable', () => {
    // Defensive: catches the failure mode where a local pattern has been
    // accidentally cleared (e.g. `regex: /(?:)/`) which would silently match
    // every line and the regex.source equality check would still pass against
    // a similarly-broken package entry.
    for (const local of LOCAL_PATTERNS) {
      expect(local.regex.source.length, `pattern=${local.name} has empty regex source`).toBeGreaterThan(2);
      expect(() => new RegExp(local.regex.source, local.regex.flags)).not.toThrow();
    }
  });
});

describe('lockstep: regex behavior parity on real-looking credential lines', () => {
  // For every local pattern, run the regex against a known-real-looking
  // sample. The matched substring from the local regex must equal the
  // matched substring from the package regex with the same source. This
  // is a tautology when regex.source equality holds — but it catches the
  // edge case where a regex compiles differently across V8 versions or
  // a flag has been silently dropped.
  //
  // Tokens are built via `[].join('')` to avoid triggering GitHub Push
  // Protection on this file itself. Precedent: credential-patterns
  // src/patterns.test.ts:11-13.
  const SAMPLES: Record<string, string> = {
    'Anthropic API Key': 'const k = "' + ['sk-ant-', 'api03-AbCdEfGhIjKlMnOp', 'QrStUv-01234567'].join('') + '"',
    'OpenAI API Key (project)': 'const k = "' + ['sk-', 'proj-AbCdEfGhIjKlMnOp', 'QrSt'].join('') + '"',
    'OpenAI API Key (legacy)': 'const k = "' + ['sk-', 'AbCdEfGhIjKlMnOpQrStUvWxYz', '0123456789AbCdEfGhIj0123'].join('') + '"',
    'AWS Access Key': 'const k = "' + ['AKIA', 'IOSFODNN7', 'REALKEY'].join('') + '"',
    'GitHub Token (fine-grained)': 'const k = "' + ['ghp_', 'abcdefghijklmnopqrstuvwxyz', '1234567890'].join('') + '"',
    'GitHub PAT (new)': 'const k = "' + ['github_', 'pat_abcdefghijklmnopqrstuv_', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXY'].join('') + '"',
    'Slack Token': 'const k = "' + ['xox', 'b-1234567890-1234567890-', 'AbCdEfGhIjKlMnOpQrStUvWx'].join('') + '"',
    'Google API Key': 'const k = "' + ['AIza', 'AbCdEfGhIjKlMnOpQrStUvWxYz', '0123456789'].join('') + '"',
    'Stripe Live Key': 'const k = "' + ['sk_', 'live_', 'abcdefghijklmnopqrstuvwx'].join('') + '"',
    'SendGrid Key': 'const k = "' + ['SG.', 'abcdefghijklmnopqrstuv.', 'abcdefghijklmnopqrstuvwxyz_-ABCDEFGHIJKLMNOPQR'].join('') + '"',
  };

  it('every mapped local pattern has a real-looking sample registered', () => {
    const missing = Object.keys(LOCAL_NAME_TO_PKG_ID).filter((name) => !(name in SAMPLES));
    expect(missing, `Patterns without a sample:\n  ${missing.join('\n  ')}`).toEqual([]);
  });

  it('local regex match on sample === package regex match on sample (per pattern)', async () => {
    const pkg = await loadPkg();
    const drift: string[] = [];

    for (const local of LOCAL_PATTERNS) {
      const sample = SAMPLES[local.name];
      if (!sample) {
        drift.push(`local=${local.name}: no sample registered`);
        continue;
      }
      const expectedId = LOCAL_NAME_TO_PKG_ID[local.name];
      const remote = pkg.CREDENTIAL_PATTERNS.find((r) => r.id === expectedId);
      if (!remote) {
        drift.push(`local=${local.name}: no package entry with id=${expectedId}`);
        continue;
      }
      const localMatch = sample.match(local.regex);
      const remoteMatch = sample.match(remote.regex);
      const localStr = localMatch ? localMatch[0] : null;
      const remoteStr = remoteMatch ? remoteMatch[0] : null;
      if (localStr !== remoteStr) {
        drift.push(`local=${local.name} (pkg=${expectedId}): local matched ${JSON.stringify(localStr)}, package matched ${JSON.stringify(remoteStr)}`);
      }
    }

    expect(drift, `Behavior drift detected:\n  ${drift.join('\n  ')}`).toEqual([]);
  });
});
