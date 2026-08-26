/**
 * The provenance abort must survive the catches that exist to swallow network
 * failures.
 *
 * Found by adversarial review 2026-08-21 on the MERGED change: the first fix
 * added a rethrow to ONE catch — the one the review reported — and left eight
 * sibling catches catching it. That is the reported-surface fix rather than the
 * class fix.
 *
 * No byte ever leaked (the read runs before the request), and — stated
 * precisely, because an earlier version of this comment did not — the message
 * was not lost either: those catches print it or put it on `publishStatus`.
 * They MISLABELLED it, rendering an internal laundering defect as a network
 * failure and then continuing. That is what this fix corrects.
 *
 * Two layers here, because a text pin alone proves nothing about behaviour and
 * a behaviour test alone cannot see a NEW catch someone adds tomorrow:
 *   1. `rethrowIfRedactionProvenance` is exercised directly.
 *   2. The count of its call sites in `cli.ts` is pinned, so a NEW catch around
 *      a publish boundary fails this test until its author classifies it.
 *
 * Both layers are weaker than they look, and saying so is cheaper than being
 * caught by it: the positional check only knows the `publishErr` spelling, and
 * the count pin is a substring count that a comment can satisfy. A catch with
 * a different variable name passes both while swallowing. What actually holds
 * this class is the reader's own tests plus these pins forcing a look.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  rethrowIfRedactionProvenance,
  RedactionProvenanceError,
} from '../../src/hardening/finding-emit';

const CLI = join(__dirname, '..', '..', 'src', 'cli.ts');

describe('rethrowIfRedactionProvenance', () => {
  // RED-PROOF: make the helper a no-op — this case goes red.
  it('rethrows a provenance failure', () => {
    const err = new RedactionProvenanceError('registry-publish', 'CRED-001', 'with no redactionStatus');
    expect(() => rethrowIfRedactionProvenance(err)).toThrow(RedactionProvenanceError);
  });

  // RED-PROOF: make the helper rethrow unconditionally — this case goes red,
  // and with it the whole reason the publish catches exist (a network failure
  // must not kill a local scan).
  it('lets an ordinary network error pass, so the catch can still swallow it', () => {
    expect(() => rethrowIfRedactionProvenance(new Error('ECONNREFUSED'))).not.toThrow();
    expect(() => rethrowIfRedactionProvenance('socket hang up')).not.toThrow();
    expect(() => rethrowIfRedactionProvenance(undefined)).not.toThrow();
  });
});

describe('every swallowing catch around a publish boundary calls the helper', () => {
  const src = readFileSync(CLI, 'utf8');

  it('the publish-path catches are all guarded', () => {
    // Each `catch (publishErr: unknown) {` must be followed immediately by the
    // helper. Checked positionally rather than by a global count, so moving a
    // call elsewhere in the file cannot satisfy this.
    const catches = [...src.matchAll(/\} catch \(publishErr: unknown\) \{\n([^\n]*)\n/g)];
    expect(catches.length, 'no publish catches found — the pattern moved and this test is vacuous').toBeGreaterThan(0);
    const unguarded = catches
      .map((m, i) => ({ i, next: m[1].trim() }))
      .filter(({ next }) => !next.startsWith('rethrowIfRedactionProvenance(publishErr)'));
    expect(unguarded, 'a publish catch would swallow the provenance abort').toEqual([]);
  });

  it('the count of guarded catches is pinned', () => {
    // Blunt on purpose, like the JSON.stringify tripwire: it does not prove
    // coverage, it forces the author of a NEW publish catch to classify it.
    const calls = (src.match(/rethrowIfRedactionProvenance\(/g) ?? []).length;
    // 9 → 10 under #602: checkPyPiPackage's arm-wide catch gained the guard
    // its URL sibling already had — an adversarial round measured it
    // swallowing a provenance abort and relabeling it a network error.
    expect(
      calls,
      'cli.ts gained or lost a rethrowIfRedactionProvenance call — a new catch around a publish boundary must call it, then update this pin',
    ).toBe(10);
  });
});
