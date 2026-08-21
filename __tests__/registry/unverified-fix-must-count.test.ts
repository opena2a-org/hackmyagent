/**
 * #285 M29 / M43 / M44 — an auto-fix that did not land must count as an
 * outstanding issue in every surface that reports findings.
 *
 * `countsAgainstScore` exists because a fix can *claim* success and be wrong.
 * `PERM-001` chmods a world-readable file and reports `fixed: true` even when
 * the write fails (immutable flag, EPERM, read-only mount); the post-fix
 * verification pass catches it and sets `fixVerified: false`. The issue is
 * still there, so every consumer has to keep counting it.
 *
 * Five consumers read that predicate and a 48-mutation pass found every one
 * of them unguarded — reverting any to a hand-rolled `!f.passed && !f.fixed`
 * left the full suite green. The consequences are not cosmetic:
 *
 *   - `buildPublishPayload` published `score: 100`, `verdict: 'pass'`,
 *     `0 failed checks` for a run the CLI exits 1 on. `score` is inside the
 *     SIGNED strong canonical, so the signature attested a figure the tool
 *     never displayed.
 *   - `reportRemediation` POSTed the disproved fix to `/remediation/remediated`
 *     while `reportFindings` POSTed the same checkId to `/remediation/track`
 *     as still open — one command, two contradictory claims.
 *   - `toASSF`, `buildScanReport` and `buildCommunityReport` dropped it from
 *     Security Hub and from the Registry package page entirely.
 *
 * These are execution tests, not source greps: each calls the real consumer
 * and asserts on what it returns or transmits. Every case is paired with a
 * genuinely-verified fix on the same shape, so a consumer that simply counts
 * everything cannot pass either.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { buildPublishPayload } from '../../src/registry/publish';
import { buildScanReport, buildCommunityReport } from '../../src/registry/client';
import { toASSF } from '../../src/output/asff';
import { reportRemediation, reportFindings } from '../../src/registry/remediation';
import { countsAgainstScore } from '../../src/ui/verdict-band';
import type { SecurityFinding } from '../../src/hardening';
import { emitFinding } from '../../src/hardening/finding-emit';
import type { SecurityFindingDraft } from '../../src/hardening/security-check';

/** The PERM-001 shape: the fix ran, the verification pass disproved it. */
// Emitted through the real boundary (unit 2): the builders under test now
// read redaction provenance on their inputs, and a fixture that fabricates
// the type without the stamps is exactly the launder the read exists to
// catch. These fixtures carry no credential bytes, so emission stamps
// 'clean' and leaves every byte the assertions read unchanged.
const UNVERIFIED_FIX: SecurityFinding = emitFinding({
  checkId: 'PERM-001',
  name: 'World-readable credential file',
  description: '.env is readable by every user on the host',
  category: 'permissions',
  severity: 'critical',
  passed: false,
  message: '.env is mode 0644',
  fixable: true,
  fixed: true,
  fixVerified: false,
  file: '.env',
} as SecurityFindingDraft);

/**
 * The same two shapes in a category that reaches a package page.
 * `buildCommunityReport` deliberately drops local dev-hygiene categories
 * (`permissions` among them) because they say nothing about the published
 * package, so the PERM-001 fixture cannot exercise that consumer.
 */
// Emitted through the real boundary (unit 2): the builders under test now
// read redaction provenance on their inputs, and a fixture that fabricates
// the type without the stamps is exactly the launder the read exists to
// catch. These fixtures carry no credential bytes, so emission stamps
// 'clean' and leaves every byte the assertions read unchanged.
const UNVERIFIED_FIX_PUBLIC: SecurityFinding = emitFinding({
  checkId: 'CRED-001',
  name: 'Hardcoded credential',
  description: 'A credential is committed in source',
  category: 'credentials',
  severity: 'critical',
  passed: false,
  message: 'credential found in config.js',
  fixable: true,
  fixed: true,
  fixVerified: false,
  file: 'config.js',
} as SecurityFindingDraft);

// Emitted through the real boundary (unit 2): the builders under test now
// read redaction provenance on their inputs, and a fixture that fabricates
// the type without the stamps is exactly the launder the read exists to
// catch. These fixtures carry no credential bytes, so emission stamps
// 'clean' and leaves every byte the assertions read unchanged.
const VERIFIED_FIX_PUBLIC: SecurityFinding = emitFinding({
  ...UNVERIFIED_FIX_PUBLIC,
  checkId: 'CRED-002',
  fixVerified: true,
} as SecurityFindingDraft);

/** Same shape, but the fix demonstrably landed. */
// Emitted through the real boundary (unit 2): the builders under test now
// read redaction provenance on their inputs, and a fixture that fabricates
// the type without the stamps is exactly the launder the read exists to
// catch. These fixtures carry no credential bytes, so emission stamps
// 'clean' and leaves every byte the assertions read unchanged.
const VERIFIED_FIX: SecurityFinding = emitFinding({
  ...UNVERIFIED_FIX,
  checkId: 'PERM-002',
  name: 'World-readable key file',
  description: 'id_rsa is readable by every user on the host',
  fixVerified: true,
  file: 'id_rsa',
} as SecurityFindingDraft);

afterEach(() => vi.restoreAllMocks());

describe('#285 an unverified fix counts as outstanding, in every consumer', () => {
  it('the predicate itself distinguishes the two shapes', () => {
    // Anchors the whole file: if these ever agree, every assertion below
    // becomes vacuous regardless of what the consumers do.
    expect(countsAgainstScore(UNVERIFIED_FIX), 'a disproved fix must count').toBe(true);
    expect(countsAgainstScore(VERIFIED_FIX), 'a confirmed fix must not count').toBe(false);
  });

  describe('M29 — buildPublishPayload (the signed strong canonical)', () => {
    const build = (findings: SecurityFinding[]) =>
      buildPublishPayload(
        { packageName: 'demo-agent', directory: '/tmp/demo', hardeningFindings: findings },
        '0.25.2',
      );

    it('does not publish a disproved fix as a passing check', () => {
      const payload = build([UNVERIFIED_FIX]);
      const published = payload.findings.find((f) => f.checkId === 'PERM-001');
      expect(published, 'the finding was dropped from the payload entirely').toBeTruthy();
      expect(
        published!.passed,
        'a fix the verification pass disproved was published as passed',
      ).toBe(false);
    });

    it('does not attest score 100 / verdict pass on a run the CLI exits 1 on', () => {
      const payload = build([UNVERIFIED_FIX]);
      expect(
        payload.verdict,
        'published verdict says pass while a CRITICAL is outstanding',
      ).toBe('fail');
      expect(
        payload.score,
        'published a perfect score for an unresolved CRITICAL — and score is signed',
      ).toBeLessThan(100);
    });

    it('still credits a fix that actually landed', () => {
      const payload = build([VERIFIED_FIX]);
      const published = payload.findings.find((f) => f.checkId === 'PERM-002');
      expect(published!.passed, 'a confirmed fix was published as still failing').toBe(true);
      expect(payload.verdict).toBe('pass');
      expect(payload.score).toBe(100);
    });
  });

  describe('M44 — the report builders', () => {
    it('buildScanReport keeps it in the vulnerability list', () => {
      const report = buildScanReport('v1', [UNVERIFIED_FIX]);
      expect(
        report.vulnerabilities.map((v) => v.id),
        'a disproved fix vanished from the Registry scan report',
      ).toContain('PERM-001');

      const clean = buildScanReport('v1', [VERIFIED_FIX]);
      expect(clean.vulnerabilities.map((v) => v.id)).not.toContain('PERM-002');
    });

    it('buildCommunityReport keeps it on the package page', () => {
      const report = buildCommunityReport('demo-agent', [UNVERIFIED_FIX_PUBLIC]);
      expect(
        report.vulnerabilities.map((v) => v.id),
        'a disproved fix vanished from the community package page',
      ).toContain('CRED-001');

      const clean = buildCommunityReport('demo-agent', [VERIFIED_FIX_PUBLIC]);
      expect(clean.vulnerabilities.map((v) => v.id)).not.toContain('CRED-002');
    });

    it('drops local-only categories for a reason unrelated to the fix predicate', () => {
      // Guards the guard: the case above would also pass if the community
      // report simply echoed everything. And if `permissions` ever stops
      // being local-only, the fixture choice above needs revisiting rather
      // than silently testing something else.
      const report = buildCommunityReport('demo-agent', [UNVERIFIED_FIX]);
      expect(
        report.vulnerabilities.map((v) => v.id),
        'a local dev-hygiene finding reached a public package page',
      ).not.toContain('PERM-001');
    });

    it('toASSF keeps it in the Security Hub export', () => {
      const asff = toASSF([UNVERIFIED_FIX], 'demo-agent');
      expect(
        asff,
        'a disproved fix was suppressed from the ASFF export',
      ).toContain('PERM-001');

      expect(toASSF([VERIFIED_FIX], 'demo-agent')).not.toContain('PERM-002');
    });
  });

  describe('M43 — remediation reporting cannot contradict itself', () => {
    /** Capture every URL the reporters POST to, per checkId. */
    async function postedEndpoints(findings: SecurityFinding[]): Promise<Map<string, string[]>> {
      const byCheck = new Map<string, string[]>();
      const bodies: { url: string; checkId: string }[] = [];

      vi.stubGlobal(
        'fetch',
        vi.fn(async (url: string, init?: { body?: string }) => {
          const parsed = JSON.parse(String(init?.body ?? '{}'));
          const checkId = parsed.findingId ?? parsed.checkId ?? '(unknown)';
          bodies.push({ url: String(url), checkId });
          return { ok: true, status: 200, json: async () => ({}) };
        }),
      );

      await reportRemediation('https://registry.test', 'scan-1', 'demo-agent', findings, 50);
      await reportFindings('https://registry.test', 'scan-1', 'demo-agent', findings, 50);

      for (const { url, checkId } of bodies) {
        byCheck.set(checkId, [...(byCheck.get(checkId) ?? []), url]);
      }
      return byCheck;
    }

    it('does not report the same checkId as both remediated and still open', async () => {
      const byCheck = await postedEndpoints([UNVERIFIED_FIX]);
      const urls = byCheck.get('PERM-001') ?? [];

      // Sanity: the reporters must have transmitted something, or this
      // proves nothing.
      expect(urls.length, 'no remediation traffic captured at all').toBeGreaterThan(0);

      const remediated = urls.filter((u) => u.includes('/remediated'));
      const tracked = urls.filter((u) => u.includes('/track'));

      expect(
        remediated.length > 0 && tracked.length > 0,
        `PERM-001 was POSTed as remediated AND as still open:\n${urls.join('\n')}`,
      ).toBe(false);
      expect(tracked.length, 'an unresolved CRITICAL was not tracked as open').toBeGreaterThan(0);
      expect(remediated.length, 'a disproved fix was reported as remediated').toBe(0);
    });

    it('still reports a fix that actually landed as remediated', async () => {
      const byCheck = await postedEndpoints([VERIFIED_FIX]);
      const urls = byCheck.get('PERM-002') ?? [];
      expect(urls.some((u) => u.includes('/remediated')), 'a confirmed fix was never reported').toBe(true);
      expect(urls.some((u) => u.includes('/track')), 'a confirmed fix was tracked as still open').toBe(false);
    });
  });
});
