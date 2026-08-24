/**
 * #367 — `fixLines` at the redaction boundary and the JSON boundary.
 *
 * The field is the line structure of `fix`, carried as a string[] beside the
 * joined string. Two properties make it safe to carry, and both are pinned
 * here because both were measured to be silently violable: the redactor's
 * field walk is string-typed, so an array steps past it and ships raw unless
 * it is walked on purpose; and structure that no longer describes the text
 * is a forged line boundary the moment a renderer prints it, so a pair that
 * disagrees must leave the boundary without its structure. The JSON contract
 * carries `fix` alone: the key is a symbol, which `JSON.stringify` never
 * serializes, at any site.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { emitFinding, emitFindings, reemitFinding } from '../../src/hardening/finding-emit';
import { FIX_LINES } from '../../src/hardening/fix-lines';
import { buildJsonStdoutDocument } from '../../src/output/json-stdout';

// A value the redactor rewrites. FAKE by construction; the shape is what the
// rule matches on, and one match is all the parity assertion needs.
const SECRET = 'sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE';

function draft(parts: readonly string[], fixOverride?: string) {
  return {
    checkId: 'AST-TEST-001',
    name: 'Test finding',
    severity: 'high' as const,
    passed: false,
    message: 'm',
    file: 'x.js',
    fix: fixOverride ?? parts.join('\n'),
    [FIX_LINES]: parts,
  };
}

describe('emitFinding walks fixLines', () => {
  it('redacts every element exactly as it redacts fix (parity, element by element)', () => {
    const parts = ['Rotate the key now.', `Found: ${SECRET} in config`, '', 'Verify: hackmyagent secure .'];
    const out = emitFinding(draft(parts) as any) as any;
    // Non-vacuity: the pass had to change something, or parity is trivially true.
    expect(out.redactionStatus).toBe('applied');
    expect(out.fix).not.toContain(SECRET);
    expect(out[FIX_LINES]).toHaveLength(parts.length);
    for (const line of out[FIX_LINES]) expect(line).not.toContain(SECRET);
    // The redacted lines still describe the redacted string.
    expect(out[FIX_LINES].join('\n')).toBe(out.fix);
  });

  it('a secret spanning a part boundary: fix is redacted and the raw parts do not leave', () => {
    // The joined string matches the password rule across the newline; no single
    // element does. Checking agreement only before the pass would carry the
    // element holding the value out under a redacted `fix`.
    const parts = ['Set password=', '"abcdefghijkl" in the config', '', 'Verify: hackmyagent secure .'];
    const out = emitFinding(draft(parts) as any) as any;
    expect(out.redactionStatus).toBe('applied');
    expect(out.fix).not.toContain('abcdefghijkl');
    expect(FIX_LINES in out).toBe(false);
    // Non-vacuity: the same parts WITHOUT the spanning secret do carry structure.
    const plain = emitFinding(draft(['Set password to a new value', 'in the config']) as any) as any;
    expect(plain[FIX_LINES]).toHaveLength(2);
  });

  it('a value that is not a string array is dropped, never walked or thrown on', () => {
    for (const bad of [[['a', 'b'], 'c'], ['a', 7], 'a\nb', 5, { join: () => 'a\nb' }, null]) {
      const out = emitFinding({ ...draft(['a', 'b']), [FIX_LINES]: bad } as any) as any;
      expect(FIX_LINES in out, JSON.stringify(bad)).toBe(false);
      expect(out.fix).toBe('a\nb');
    }
  });

  it('a pair that disagrees leaves without its structure, and fix is untouched', () => {
    const parts = ['line one', 'line two'];
    const out = emitFinding(draft(parts, 'a fix rewritten after composition') as any) as any;
    expect(out.fix).toBe('a fix rewritten after composition');
    expect(FIX_LINES in out).toBe(false);
  });

  it('a pair that agrees is carried through the array boundary too', () => {
    const [out] = emitFindings([draft(['a', 'b']) as any]) as any[];
    expect(out[FIX_LINES]).toEqual(['a', 'b']);
  });

  it('reemitFinding with a new fix drops the stale structure', () => {
    const prior = emitFinding(draft(['a', 'b']) as any);
    const out = reemitFinding(prior, { fix: 'c' }) as any;
    expect(out.fix).toBe('c');
    expect(FIX_LINES in out).toBe(false);
    // And a re-emit that keeps fix keeps the structure.
    const same = reemitFinding(prior, { severity: 'low' }) as any;
    expect(same[FIX_LINES]).toEqual(['a', 'b']);
  });

  it('a finding without the structure is exactly what it was', () => {
    const plain: any = draft(['a', 'b']);
    delete plain[FIX_LINES];
    const out = emitFinding(plain) as any;
    expect(FIX_LINES in out).toBe(false);
    expect(out.fix).toBe('a\nb');
  });
});

describe('no JSON channel can carry the structure, by construction', () => {
  it('a bare JSON.stringify at any site, and the stamped document, carry fix alone', () => {
    const f = emitFinding(draft(['a', 'b']) as any) as any;
    expect(f[FIX_LINES]).toEqual(['a', 'b']);
    // The property the string field leaked through: a raw stringify with no
    // replacer, as `secure --output`, `detect --json` and the report writers do.
    for (const text of [JSON.stringify(f), JSON.stringify({ ...f }), JSON.stringify([f], null, 2)]) {
      expect(text).not.toContain('fixLines');
      // Neither the key nor the array it held: the structure is absent, not renamed.
      expect(text).not.toContain('["a","b"]');
      expect(text).not.toContain('"a",\n');
      expect(JSON.parse(text.startsWith('[') ? text : `[${text}]`)[0].fix).toBe('a\nb');
    }
    const doc = buildJsonStdoutDocument({ findings: [f], nested: { details: [f] } }, '0.0.0-test');
    expect(doc).not.toContain('fixLines');
    expect(JSON.parse(doc).nested.details[0].fix).toBe('a\nb');
  });

  it('object spread carries the structure between the bridge and the renderer', () => {
    const f = emitFinding(draft(['a', 'b']) as any) as any;
    expect(({ ...f } as any)[FIX_LINES]).toEqual(['a', 'b']);
    expect(({ ...f, suppressed: true } as any)[FIX_LINES]).toEqual(['a', 'b']);
  });
});

describe('only the fix generator writes the structure', () => {
  // The CISO ruling for this unit names "any producer other than fix-generator
  // populating fixLines" as the likeliest way the invariants erode. A second
  // producer that does not compose from developer-authored parts would be
  // asserting structure it did not author. The bridge copies the field and the
  // boundary walks it; nothing else may write it.
  const ALLOWED = new Set([
    'nanomind-core/fix-generator.ts',
    'nanomind-core/scanner-bridge.ts',
    'hardening/finding-emit.ts',
  ]);

  function writers(): string[] {
    const root = join(__dirname, '..', '..', 'src');
    const out: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) { walk(p); continue; }
        if (!p.endsWith('.ts')) continue;
        readFileSync(p, 'utf-8').split('\n').forEach((line, i) => {
          const code = line.replace(/\/\/.*$/, '');
          // A write is a computed object-literal key or a property assignment
          // under the symbol; the interface declarations are type text, not writes.
          const isWrite = /\[FIX_LINES\]\s*[:=](?!=)/.test(code);
          const isTypeAnnotation = /\[FIX_LINES\]\??:\s*(readonly )?string\[\]/.test(code);
          if (isWrite && !isTypeAnnotation && !/^\s*\*/.test(line)) {
            out.push(`${p.slice(root.length + 1)}:${i + 1}`);
          }
        });
      }
    };
    walk(root);
    return out;
  }

  it('every write of the structure under src/ is in the generator, the bridge, or the boundary', () => {
    const found = writers();
    // Non-vacuity: the three known writers must be seen, or the scan read nothing.
    expect(found.some((w) => w.startsWith('nanomind-core/fix-generator.ts:'))).toBe(true);
    expect(found.some((w) => w.startsWith('nanomind-core/scanner-bridge.ts:'))).toBe(true);
    expect(found.some((w) => w.startsWith('hardening/finding-emit.ts:'))).toBe(true);
    const strangers = found.filter((w) => !ALLOWED.has(w.replace(/:\d+$/, '')));
    expect(strangers, strangers.join('\n')).toEqual([]);
  });
});
