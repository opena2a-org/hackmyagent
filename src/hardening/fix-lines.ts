/**
 * #367 — the key under which a finding carries the authored line structure of
 * its `fix`: one element per line the producer wrote, `join('\\n') === fix`.
 *
 * A symbol, on purpose. `JSON.stringify` never serializes a symbol-keyed
 * property, so the structure cannot reach a JSON channel — a `--json`
 * document, an `--output` file, a report written to disk, a Registry payload —
 * from ANY stringify site, without a replacer at each one; the text channel is
 * the only reader. Object spread copies an enumerable symbol property, so it
 * survives the copies a finding goes through between the bridge and the
 * renderer. `Symbol.for` so a second copy of this module (dist beside src in
 * one test process) resolves the same key.
 */
export const FIX_LINES: unique symbol = Symbol.for('hackmyagent.fixLines');

/** What a finding that carries the structure looks like to a reader. */
export interface FixLinesCarrier {
  readonly [FIX_LINES]?: readonly string[];
}
