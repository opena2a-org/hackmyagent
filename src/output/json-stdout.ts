/**
 * The JSON-stdout document builder: version stamp + the publish-boundary read.
 *
 * Extracted from `cli.ts` (unit 2 of the redaction-boundary hardening) so the
 * chokepoint is IMPORTABLE — the 2026-08-21 ruling requires every publish
 * boundary's read to be proven by runtime injection through the real builder,
 * and a function buried in the CLI entrypoint cannot be injected without
 * spawning. `cli.ts`'s `writeJsonStdout` delegates here; ~32 JSON surfaces
 * flow through this one function.
 */
import { assertRedactionProvenance } from '../hardening/finding-emit';
import { escapeJsonDisplayHazards } from '../ui/display-safe';

/**
 * `JSON.stringify` for a `--json` document a terminal may print (#1046): DEL,
 * C1, bidi, format and line-separator code points taken from a path are written
 * as `\uXXXX` escapes, which every JSON parser reads back as the real bytes.
 * Emitters that do not go through `buildJsonStdoutDocument` (a `--output` file,
 * a `--format json` arm with its own writer) serialize through this instead.
 */
export function stringifyJsonOutput(value: unknown, space?: number): string {
  // `JSON.stringify(undefined)` is undefined at runtime despite its type.
  const json = JSON.stringify(value, null, space);
  return typeof json === 'string' ? escapeJsonDisplayHazards(json) : json;
}

/**
 * Assert redaction provenance over the payload, stamp the producing version,
 * and serialize. Throws `RedactionProvenanceError` (never writes) if any
 * finding-shaped value in the payload lacks provenance.
 *
 * Version stamping semantics preserved from the original `writeJsonStdout`
 * (#202): only plain objects are stamped — arrays and scalars would change
 * shape — and an existing `hackmyagentVersion` is never overwritten, so a
 * payload that deliberately reports a different version keeps it.
 */
export function buildJsonStdoutDocument(data: unknown, version: string): string {
  assertRedactionProvenance(data, 'json-stdout');
  const stamped =
    data && typeof data === 'object' && !Array.isArray(data)
      ? { hackmyagentVersion: version, ...(data as Record<string, unknown>) }
      : data;
  return stringifyJsonOutput(stamped, 2) + '\n';
}
