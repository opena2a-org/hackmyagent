/**
 * HMA-23 — `SemanticCompiler.compile()` must not throw `RangeError` on
 * multi-megabyte unbroken runs reachable through the public library entry.
 *
 * THE DEFECT. The credential patterns the compiler runs — the canonical list in
 * `semantic-compiler.ts` and its redaction mirror in
 * `security/defense-in-depth.ts` — mostly end in an unbounded lower-bound
 * quantifier over one character class (`{20,}`, `{48,}`, `{24,}`, `{10,}`,
 * `{40,}`). On an unbroken same-alphabet run those do not get slow, they THROW:
 * V8 runs its backtrack stack out and `exec`/`replace` raise `RangeError:
 * Maximum call stack size exceeded` past ~5 MB. Nothing bounded the library
 * path, so the throw escaped `compile()` to the caller.
 *
 * Reachability is not hypothetical. `SemanticCompiler` is exported from
 * `src/nanomind-core/index.ts` and packaged as the `./nanomind-core` export, and
 * two in-tree readers (`src/soul/scanner.ts`, `src/narrative/wire-publish.ts`)
 * read a file and call `compile()` with no size check at all.
 *
 * WHY A SIZE GATE AND NOT A NARROWER QUANTIFIER. Capping `{20,}` at some
 * `{20,N}` relocates the blind spot to the first credential longer than N rather
 * than removing it; AC3 pins that none of the quantifiers moved.
 *
 * WHY THE REFUSAL IS LOUD. An unscanned artifact returned clean is the C1
 * incident class — a credential input stamped benign. AC2 pins that a refusal
 * arrives as a named warning AND a deterministic finding, on the fresh-compile
 * path and on the cache-hit path.
 *
 * Every credential-shaped value below is synthetic filler from a fixed
 * non-secret alphabet. None is or ever was a live credential.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

// Through the PACKAGE ENTRY, not the compiler module: AC1 is a statement about
// what a library consumer of `./nanomind-core` gets, and importing the inner
// module would not exercise the export that consumer actually resolves.
import { SemanticCompiler } from '../../src/nanomind-core/index';
import {
  canonicalCredentialPatternsForTest,
  nameGatedCredentialPatternsForTest,
  maxCredentialScanBytesForTest,
} from '../../src/nanomind-core/compiler/semantic-compiler';

const repoFile = (rel: string) =>
  readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)), 'utf-8');

/** The two probe inputs AC1 names, verbatim. */
const SIX_MB_RUN = 'A'.repeat(6 * 1024 * 1024);
const PROBES: Array<{ name: string; content: string }> = [
  { name: 'name-gated AWS assignment', content: `AWS_SECRET_ACCESS_KEY = "${SIX_MB_RUN}"` },
  { name: 'canonical Anthropic prefix', content: `sk-ant-api03-${SIX_MB_RUN}` },
];

/**
 * `useNanoMind: false` keeps the daemon off the wire; it does not skip anything
 * this task is about. The credential scan and the redaction mirror are both in
 * the deterministic layer, which runs before and independently of inference.
 */
const compiler = () => new SemanticCompiler({ useNanoMind: false });

/**
 * Synthetic filler: alphanumeric, none of the placeholder markers the FP filters
 * strip, and enough distinct characters to clear the name-gated rule's
 * low-entropy sentinel check (a run of one repeated character is a redaction
 * placeholder, not a secret, and is dropped on purpose).
 */
const ALPHABET = 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Ab6Cd7Ef8Gh9Ij0Kl1Mn2Op3';
const fill = (n: number) => ALPHABET.repeat(Math.ceil(n / ALPHABET.length)).slice(0, n);

describe('HMA-23 credential scan size gate', () => {
  describe('AC1 — compile() survives a multi-megabyte unbroken run', () => {
    for (const probe of PROBES) {
      it(`HMA-23.AC1 compile() returns a result rather than throwing RangeError on a 6 MB ${probe.name}`, async () => {
        // Red-first at 446771a: both probes rejected with `RangeError: Maximum
        // call stack size exceeded`, the AWS one out of the redaction mirror via
        // `extractDeclaredPurpose` and the Anthropic one likewise.
        await expect(compiler().compile(probe.content, 'x.py')).resolves.toBeDefined();
      }, 120_000);

      it(`HMA-23.AC1 the 6 MB ${probe.name} produces a finding or a named refusal, never silence`, async () => {
        const result = await compiler().compile(probe.content, 'x.py');
        const refused = result.warnings.some(w => w.includes('Credential scan skipped'));
        // One or the other must be true. Both being false is the failure this
        // criterion exists to catch: a result that carries neither a finding nor
        // a reason there is no finding.
        expect(refused || result.deterministicFindings.length > 0).toBe(true);
      }, 120_000);
    }

    it('HMA-23.AC1 SemanticCompiler is reachable as the packaged "./nanomind-core" export', () => {
      // The reachability claim, read off the tree rather than assumed. The
      // export map points at `dist/`, which is gitignored and not built here, so
      // the two halves are checked separately: the map names the entry, and the
      // entry's SOURCE exports the class.
      const pkg = JSON.parse(repoFile('package.json')) as { exports: Record<string, string> };
      expect(pkg.exports['./nanomind-core']).toBe('./dist/nanomind-core/index.js');
      expect(repoFile('src/nanomind-core/index.ts'))
        .toContain("export { SemanticCompiler } from './compiler/semantic-compiler.js';");
      expect(typeof SemanticCompiler).toBe('function');
    });
  });

  describe('AC2 — a size refusal is named, and never a clean success', () => {
    it('HMA-23.AC2 the refusal names itself in warnings and says the content was not scanned', async () => {
      const result = await compiler().compile(PROBES[0].content, 'x.py');
      const refusal = result.warnings.find(w => w.startsWith('Credential scan skipped'));
      expect(refusal).toBeDefined();
      // Bounded: it reports the size it refused and the limit it refused against,
      // so a consumer can tell "too big" from "scanner broke".
      expect(refusal).toContain(String(Buffer.byteLength(PROBES[0].content, 'utf-8')));
      expect(refusal).toContain(String(maxCredentialScanBytesForTest()));
      expect(refusal).toContain('No credential pattern was evaluated against this content');
    }, 120_000);

    it('HMA-23.AC2 a refused credential-bearing artifact is not returned finding-free', async () => {
      const result = await compiler().compile(PROBES[0].content, 'x.py');
      // The C1 shape, stated as the thing that must NOT happen: zero findings on
      // an input the compiler declined to read.
      expect(result.deterministicFindings.length).toBeGreaterThan(0);
      expect(result.deterministicFindings.map(f => f.surface))
        .toContain('Credential scan not performed (artifact over size limit)');
    }, 120_000);

    it('HMA-23.AC2 a refused artifact is not classified benign', async () => {
      const result = await compiler().compile(PROBES[0].content, 'x.py');
      // A warnings-only refusal would still hand back `benign` with an empty
      // finding list, which reads downstream as a pass. The refusal goes into the
      // deterministic list precisely so the floor lifts it off benign.
      expect(result.ast.intentClassification).not.toBe('benign');
      expect(result.ast.inferredRiskSurface.map(s => s.surface))
        .toContain('Credential scan not performed (artifact over size limit)');
    }, 120_000);

    it('HMA-23.AC2 the refusal survives the cache hit, which is the path that would drop it', async () => {
      const c = compiler();
      await c.compile(PROBES[0].content, 'x.py');
      // Second compile of byte-identical content: served from cache, which
      // replaces `warnings` wholesale and would otherwise return the refusal's
      // findings under a warning list that no longer explains them.
      const second = await c.compile(PROBES[0].content, 'x.py');
      expect(second.warnings).toContain('Served from cache');
      expect(second.warnings.some(w => w.startsWith('Credential scan skipped'))).toBe(true);
      expect(second.deterministicFindings.map(f => f.surface))
        .toContain('Credential scan not performed (artifact over size limit)');
      expect(second.ast.intentClassification).not.toBe('benign');
    }, 120_000);

    it('HMA-23.AC2 the redaction mirror withholds oversized content rather than passing it through', async () => {
      // The second throw site, and the one that fails DANGEROUSLY if it is fixed
      // by returning the input untouched: `redactSecretsForReport` is the last
      // thing between a live secret and `declaredPurpose`, which is rendered to
      // users. Refusing must not mean passing through.
      const result = await compiler().compile(PROBES[0].content, 'x.py');
      expect(result.ast.declaredPurpose).not.toContain(SIX_MB_RUN.slice(0, 64));
      expect(result.ast.declaredPurpose.length).toBeLessThanOrEqual(200);
    }, 120_000);
  });

  describe('AC3 — detection is not narrowed by the gate', () => {
    it('HMA-23.AC3 a 1000-character sk-ant-api03 credential still yields the Anthropic API key finding', async () => {
      const result = await compiler().compile(`const k = "sk-ant-api03-${fill(1000)}";\n`, 'x.py');
      expect(result.deterministicFindings.map(f => f.surface)).toContain('Hardcoded Anthropic API key');
    });

    it('HMA-23.AC3 no credential pattern trades its unbounded lower bound for a fixed or capped width', () => {
      // Read off the LIVE regexes, not a restatement of them: a test carrying its
      // own copy of the patterns cannot notice the real ones changing. `{N,M}`
      // would be the tempting "fix" — it moves the blind spot to the first
      // credential longer than M instead of removing it, and pass 21 measured
      // real values at 257, 300 and 1000 characters against a proposed `{40,256}`.
      const patterns = [...canonicalCredentialPatternsForTest(), ...nameGatedCredentialPatternsForTest()];
      const expectedUnbounded: Record<string, string> = {
        'Anthropic API key': '{20,}',
        'OpenAI project key': '{20,}',
        'OpenAI legacy key': '{48,}',
        'Slack bot token': '{10,}',
        'Stripe live key': '{24,}',
        'AWS secret access key': '{40,}',
      };
      for (const [label, quantifier] of Object.entries(expectedUnbounded)) {
        const pattern = patterns.find(p => p.label === label);
        expect(pattern, `pattern list no longer carries "${label}"`).toBeDefined();
        expect(pattern!.regex.source, `${label} lost its unbounded lower bound`).toContain(quantifier);
        // The same lower bound must not have grown an upper one: `{20,}` is the
        // invariant, `{20,256}` is the regression wearing it as a disguise.
        const lowerBound = quantifier.slice(1, -2);
        expect(pattern!.regex.source, `${label} capped its lower bound at an upper one`)
          .not.toMatch(new RegExp(`\\{${lowerBound},\\d`));
      }
      // And no pattern in either list acquired a capped range on a credential
      // BODY. Anchored on `]` so it reads only widths applied to a character
      // class: the AWS rule's `.{0,16}` is a proximity window between the name
      // anchor and the value, not a width, and capping it is not this defect.
      for (const { label, regex } of patterns) {
        expect(regex.source, `${label} acquired a capped-range body quantifier`)
          .not.toMatch(/\]\{\d+,\d+\}/);
      }
    });

    it('HMA-23.AC3 the gate sits above any credential a pattern could match, so nothing real is refused', () => {
      // The gate is only honest if the refusal band starts far above the longest
      // credential these patterns exist to catch. 1 MiB against a 1000-character
      // key is three orders of magnitude of headroom.
      expect(maxCredentialScanBytesForTest()).toBeGreaterThan(1000 * 100);
    });

    it('HMA-23.AC3 detection still reaches the last byte below the gate, on an unbroken run', async () => {
      // The band the gate did NOT take away, exercised at its far edge and in
      // the shape that motivated the gate: one unbroken ~1.04 MB same-alphabet
      // run behind an AWS name anchor. This is the case that would throw at
      // 6 MB, and the greedy `{40,}` still consumes the whole run and reports
      // it here. A gate that had been set too low, or a `{40,N}` cap, would
      // both show up as a missing finding on exactly this input.
      const content = `AWS_SECRET_ACCESS_KEY = "${fill(1_040_000)}"`;
      expect(Buffer.byteLength(content, 'utf-8')).toBeLessThan(maxCredentialScanBytesForTest());
      const result = await compiler().compile(content, 'x.py');
      expect(result.deterministicFindings.map(f => f.surface)).toContain('Hardcoded AWS secret access key');
      expect(result.warnings.some(w => w.startsWith('Credential scan skipped'))).toBe(false);
    }, 120_000);
  });

  describe('AC1 — the scanned band is safe right up to the gate', () => {
    it('HMA-23.AC1 an unbroken run at the gate boundary is scanned without throwing', async () => {
      // The gate only makes `compile()` safe if everything BELOW it is safe, so
      // the worst input that still gets handed to the patterns — a single
      // unbroken same-alphabet run filling the whole allowance — is the one
      // worth pinning. Measured at 50ms, against a `RangeError` past ~5 MB.
      const content = `AWS_SECRET_ACCESS_KEY = "${'A'.repeat(maxCredentialScanBytesForTest() - 32)}"`;
      expect(Buffer.byteLength(content, 'utf-8')).toBeLessThanOrEqual(maxCredentialScanBytesForTest());
      await expect(compiler().compile(content, 'x.py')).resolves.toBeDefined();
    }, 120_000);
  });

  describe('AC4 — the comment names the cap that actually governs this path', () => {
    const compilerSource = repoFile('src/nanomind-core/compiler/semantic-compiler.ts');

    it('HMA-23.AC4 the GitLab ReDoS note no longer cites a 10 MB file cap', () => {
      // `10 MB` here was `MAX_FILE_SIZE` from `src/hardening/scanner.ts`, a
      // different component that never feeds this scan. The margin it documented
      // was 10x too generous in the dangerous direction.
      expect(compilerSource).not.toContain('against a 10 MB file cap');
    });

    it('HMA-23.AC4 the note cites MAX_FILE_SIZE = 1_048_576 in scanner-bridge.ts instead', () => {
      // Comment prefixes and line wrapping stripped before matching, so a reflow
      // of the paragraph does not read as the fix being reverted.
      const prose = compilerSource.replace(/^\s*\/\/ ?/gm, '').replace(/\s+/g, ' ');
      expect(prose).toContain('1 MiB cap that actually governs this path');
      expect(prose).toContain('`MAX_FILE_SIZE = 1_048_576` in `src/nanomind-core/scanner-bridge.ts`');
      // And it says where the 10 MB number really belongs, so the next reader
      // does not re-derive the same wrong margin from the same wrong place.
      expect(prose).toContain('`src/hardening/scanner.ts`');
    });

    it('HMA-23.AC4 the cited cap is a fact about the tree, not just text in a comment', () => {
      // The comment is only a fix if what it now says is true. Both halves are
      // checked at their source, so the comment cannot drift back into fiction
      // by either number moving.
      expect(repoFile('src/nanomind-core/scanner-bridge.ts')).toContain('const MAX_FILE_SIZE = 1_048_576;');
      expect(repoFile('src/hardening/scanner.ts')).toContain('const MAX_FILE_SIZE = 10 * 1024 * 1024;');
      // And the gate the compiler applies matches the cap the comment cites, so
      // the library path and the CLI path refuse the same inputs.
      expect(maxCredentialScanBytesForTest()).toBe(1_048_576);
    });
  });
});
