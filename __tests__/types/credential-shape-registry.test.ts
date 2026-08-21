/**
 * The credential shape registry's own contract.
 *
 * Every expectation is a hand-written literal in
 * `__tests__/helpers/credential-shape-fixtures.ts`. Nothing here derives an
 * expectation from the implementation, because the prior art did exactly that
 * and stayed 197-assertions green over two live leaks: its corpus was generated
 * by mapping over the detector's own list, so deleting a shape deleted its test
 * case, and its oracle called the same `matchVendorPrefix` the redactor uses,
 * so an over-claiming prefix shrank the expected body by precisely the bytes
 * that leaked.
 */
import { describe, it, expect } from 'vitest';
import {
  CREDENTIAL_SHAPES,
  CREDENTIAL_REDACTION_MARKERS,
  CREDENTIAL_KEY_NAMES,
  VENDOR_PREFIX_ALTERNATIVES,
  keyNameDelimiterPattern,
  shapeAlternation,
  shapesFor,
  type CredentialShape,
  type ShapeId,
} from '../../src/types/credential-format';
import {
  SHAPE_FIXTURES,
  EXPECTED_GUARDS,
  EXPECTED_VENDOR_ALTERNATIVES,
} from '../helpers/credential-shape-fixtures';

const byId = new Map<string, CredentialShape>(CREDENTIAL_SHAPES.map(s => [s.id, s]));

describe('credential shape registry — id set', () => {
  it('every registry shape has a hand-written fixture', () => {
    const missing = CREDENTIAL_SHAPES.map(s => s.id).filter(id => !(id in SHAPE_FIXTURES));
    expect(missing).toEqual([]);
  });

  it('every fixture names a registry shape — no orphans', () => {
    const orphans = Object.keys(SHAPE_FIXTURES).filter(id => !byId.has(id));
    expect(orphans).toEqual([]);
  });

  it('ids are unique', () => {
    expect(new Set(CREDENTIAL_SHAPES.map(s => s.id)).size).toBe(CREDENTIAL_SHAPES.length);
  });
});

describe('credential shape registry — patterns, never labels', () => {
  // Enumerating by label is the weakness this replaces. `xoxb-`, `xoxp-`,
  // `xoxa-`, `xoxr-` and `xoxs-` all report as one label, so narrowing the
  // pattern to `xoxb-` is invisible to any label-set assertion — and the guard
  // this supersedes carved out `PEM private key`, the one shape that leaked a
  // full 40-byte body.
  for (const id of Object.keys(SHAPE_FIXTURES)) {
    it(`${id}: composed alternation matches the hand-written source`, () => {
      const shape = byId.get(id);
      expect(shape, `no registry shape for fixture ${id}`).toBeDefined();
      expect(shapeAlternation(shape!)).toBe(SHAPE_FIXTURES[id].alternation);
    });
  }

  it('the vendor alternation is byte-identical to the hand-written list, in order', () => {
    expect(VENDOR_PREFIX_ALTERNATIVES).toEqual(EXPECTED_VENDOR_ALTERNATIVES);
  });

  it('the vendor alternation carries exactly the vendor-alternation surface', () => {
    expect(shapesFor('vendor-alternation').map(s => s.id)).toEqual([
      'anthropic-key',
      'openai-project-key',
      'openai-key',
      'stripe-live',
      'stripe-test',
      'github-pat',
      'github-oauth',
      'github-server',
      'github-user',
      'github-fine-grained',
      'huggingface-token',
      'gitlab-pat',
      'npm-token',
      'aws-access-key-id',
      'google-api-key',
      'slack-token',
      'sendgrid-key',
    ]);
  });
});

describe('credential shape registry — each shape matches its own fixture and rejects the near miss', () => {
  for (const id of Object.keys(SHAPE_FIXTURES)) {
    const fixture = SHAPE_FIXTURES[id];
    if (fixture.alternation === '') continue; // jwt: matched by scan, asserted below
    it(`${id}: sample matches, near miss does not`, () => {
      const re = new RegExp(`^(?:${fixture.alternation})$`);
      expect(re.test(fixture.sample), `sample should match ${id}`).toBe(true);
      expect(re.test(fixture.nearMiss), `near miss should NOT match ${id}`).toBe(false);
    });
  }

  it('jwt is the only shape with no regex source', () => {
    const sourceless = CREDENTIAL_SHAPES.filter(
      s => s.kind === 'structural' && s.source === '',
    ).map(s => s.id);
    expect(sourceless).toEqual(['jwt']);
  });
});

describe('credential shape registry — marker totality', () => {
  it('every shape has a marker', () => {
    const unmarked = CREDENTIAL_SHAPES.filter(
      s => CREDENTIAL_REDACTION_MARKERS[s.id] === undefined,
    ).map(s => s.id);
    expect(unmarked).toEqual([]);
  });

  it('every marker names a shape — no orphan markers', () => {
    const orphans = (Object.keys(CREDENTIAL_REDACTION_MARKERS) as ShapeId[]).filter(
      id => !byId.has(id),
    );
    expect(orphans).toEqual([]);
  });

  it('markers match the hand-written expectations', () => {
    for (const id of Object.keys(SHAPE_FIXTURES)) {
      expect(CREDENTIAL_REDACTION_MARKERS[id as ShapeId], id).toBe(SHAPE_FIXTURES[id].marker);
    }
  });

  it('a marker is a constant name, never a preview of the value', () => {
    // The historical defect this closes printed the first 8 characters of an
    // unknown-shape value into evidence — 5 characters of live `hf_` body. A
    // marker that can carry body bytes is that defect one layer down.
    //
    // The property that separates a name from a preview is that a name is
    // drawn from a fixed uppercase vocabulary: no lowercase, no digits, no
    // separators other than `_`. Credential bodies are mixed-case alphanumeric
    // by construction, so any leaked byte fails this.
    //
    // A byte-run comparison against the sample cannot express this: the PEM
    // sample is a HEADER (`-----BEGIN RSA PRIVATE KEY-----`) and shares the
    // English word PRIVATE_KEY with its own marker, which is naming, not
    // leaking.
    for (const id of Object.keys(SHAPE_FIXTURES)) {
      expect(SHAPE_FIXTURES[id].marker, id).toMatch(/^\[REDACTED(?:_[A-Z]+)*\]$/);
    }
  });

  it('the marker vocabulary is small and shared, so a marker cannot encode a value', () => {
    // 22 shapes, far fewer markers: GitHub's five token types share one, and
    // Stripe's two share one. A per-value marker would show up here as a
    // marker count approaching the shape count.
    const markers = new Set(Object.values(CREDENTIAL_REDACTION_MARKERS));
    expect(markers.size).toBeLessThan(CREDENTIAL_SHAPES.length);
    expect(markers.size).toBe(16); // 22 shapes: GitHub 5 -> 1, OpenAI 2 -> 1, Stripe 2 -> 1
  });
});

describe('credential shape registry — guards', () => {
  it('every shape declares at least one guard literal', () => {
    expect(CREDENTIAL_SHAPES.filter(s => s.guards.length === 0).map(s => s.id)).toEqual([]);
  });

  it('guards match the hand-written expectations', () => {
    for (const id of Object.keys(EXPECTED_GUARDS)) {
      const shape = byId.get(id);
      expect(shape, id).toBeDefined();
      expect([...shape!.guards], id).toEqual([...EXPECTED_GUARDS[id]]);
    }
  });

  it('every registry shape appears in the hand-written guard map', () => {
    expect(CREDENTIAL_SHAPES.map(s => s.id).filter(id => !(id in EXPECTED_GUARDS))).toEqual([]);
  });
});

describe('credential shape registry — surfaces carry their reason', () => {
  const ALL: readonly string[] = [
    'format-scan',
    'vendor-alternation',
    'ast-canonical',
    'nanomind-redaction',
  ];

  it('a shape that does not reach every surface says why', () => {
    const silent = CREDENTIAL_SHAPES.filter(
      s => !ALL.every(surface => s.surfaces.has(surface as never)) && !s.rationale,
    ).map(s => s.id);
    expect(silent).toEqual([]);
  });

  it('the ast-canonical surface carries exactly 12 shapes', () => {
    // Pinned so the count cannot move — in either direction — without a
    // recorded decision. 22 shapes are known to this tree and 12 of them can
    // produce a finding; that ten-shape gap is the whole of the detection
    // half of this unit, and it is the number a reader should be able to cite.
    expect(shapesFor('ast-canonical').length).toBe(12);
  });

  it('a rationale is a reason, not a restatement of the fact', () => {
    // A shape's absence from a surface is either a measured decision or an
    // undeclared gap, and the record has to say WHICH. The failure this pins
    // is a rationale that reads like a finding while carrying no measurement —
    // five shapes here once said "Absent from CANONICAL_CREDENTIAL_PATTERNS.
    // Same one-at-a-time re-add", which restates the surface set the reader
    // just looked at.
    //
    // Two rules. Every rationale cites a file:line, so it can be checked. And
    // a rationale shared by more than one shape must announce that it is an
    // UNDECLARED GAP rather than pose as a per-shape measurement.
    const byRationale = new Map<string, string[]>();
    for (const shape of CREDENTIAL_SHAPES) {
      if (!shape.rationale) continue;
      expect(shape.rationale, `${shape.id} rationale cites no file:line`).toMatch(/\.ts:\d+/);
      byRationale.set(shape.rationale, [...(byRationale.get(shape.rationale) ?? []), shape.id]);
    }
    for (const [rationale, ids] of byRationale) {
      if (ids.length === 1) continue;
      expect(rationale, `${ids.join(', ')} share a rationale that claims to be measured`).toContain(
        'UNDECLARED GAP',
      );
    }
  });

  it('the measured divergences are still the ones recorded', () => {
    // These four are the deliberate, measured exclusions. If one of them
    // becomes total, the reason it was excluded has been resolved or lost —
    // either way this test is the place that says so.
    expect(byId.get('gitlab-pat')!.surfaces.has('ast-canonical')).toBe(false);
    expect(byId.get('jwt')!.surfaces.has('nanomind-redaction')).toBe(false);
    expect(byId.get('sendgrid-key')!.surfaces.has('ast-canonical')).toBe(false);
    expect(byId.get('entropy-blob')!.surfaces.has('nanomind-redaction')).toBe(false);
  });
});

describe('credential key names', () => {
  it('carries the union of the four live vocabularies', () => {
    // Hand-written from the four sites, not imported from any of them:
    //   scanner/detect.ts:496, scanner/permission-vocabulary.ts:415,
    //   nanomind-core/security/defense-in-depth.ts:270,
    //   semantic/structural/credential-context.ts:29
    for (const name of [
      'api_key',
      'apikey',
      'secret',
      'token',
      'password',
      'passwd',
      'pwd',
      'authorization',
      'key',
      'client_secret',
      'session_secret',
      'db_password',
    ]) {
      expect(CREDENTIAL_KEY_NAMES, `missing ${name}`).toContain(name);
    }
  });

  it('has no duplicates', () => {
    expect(new Set(CREDENTIAL_KEY_NAMES).size).toBe(CREDENTIAL_KEY_NAMES.length);
  });

  it('the delimiter steps over no scheme word', () => {
    // Every optional atom between the two `\s*` runs makes the pair ambiguous
    // and the match quadratic: a `(?:bearer|basic|token)?` group here took
    // `detect` from 0.25s to 51s on a 200 KB config.
    const source = keyNameDelimiterPattern().source;
    expect(source).toBe('\\s*[:=]\\s*["\']?');
    expect(source.toLowerCase()).not.toContain('bearer');
  });

  it('returns a fresh RegExp each call', () => {
    expect(keyNameDelimiterPattern()).not.toBe(keyNameDelimiterPattern());
  });

  it('matches the separators the live sites match', () => {
    for (const sep of [': ', '=', ' = ', ':"', '= "']) {
      expect(new RegExp(`^${keyNameDelimiterPattern().source}$`).test(sep), sep).toBe(true);
    }
  });
});
