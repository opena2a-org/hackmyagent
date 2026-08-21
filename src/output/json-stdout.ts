/**
 * The JSON-stdout document builder: version stamp + the publish-boundary read.
 *
 * Extracted from `cli.ts` (unit 2 of the redaction-boundary hardening) so the
 * chokepoint is IMPORTABLE — `[CHIEF-CISO]` 2026-08-21 requires every publish
 * boundary's read to be proven by runtime injection through the real builder,
 * and a function buried in the CLI entrypoint cannot be injected without
 * spawning. `cli.ts`'s `writeJsonStdout` delegates here; ~32 JSON surfaces
 * flow through this one function.
 */
import { assertRedactionProvenance } from '../hardening/finding-emit';

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
  return JSON.stringify(stamped, null, 2) + '\n';
}
