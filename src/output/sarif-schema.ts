/**
 * The `$schema` every SARIF document this tool writes points at (#394).
 *
 * It is the schema's own `$id`: the OASIS-published SARIF 2.1.0 errata01
 * schema. The previous pointer, the `master` branch of the oasis-tcs/sarif-spec
 * repository, returns 404 since that repository moved the file to `main`, so an
 * editor or validator that resolved `$schema` fetched nothing. The OASIS URL is
 * the one the schema names for itself and does not depend on a branch name.
 *
 * One constant for all three writers (`secure -f sarif`, the benchmark SARIF
 * and `attack` SARIF), so the pointer cannot drift between them again.
 */
export const SARIF_SCHEMA_URL =
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';
