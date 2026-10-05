/**
 * Finding-id prefixes that belong to the opena2a CLI.
 *
 * `opena2a review` lists hackmyagent's findings and the CLI's own in one
 * `findings` array. When both tools use one id for two different checks,
 * anything keyed on the id (a suppression list, a dashboard, `explain`) reads
 * them as the same finding. The CLI mints its ids under the prefixes below,
 * so no hackmyagent check id begins with one of them.
 * __tests__/repo/cli-owned-id-prefixes.test.ts enforces that over every id
 * `explain` answers for and every string literal under src/.
 *
 * This is the only copy of the list. When the CLI starts minting ids under a
 * new prefix, add it here.
 */
export const CLI_OWNED_ID_PREFIXES: readonly string[] = Object.freeze([
  // Findings from `opena2a detect`: DETECT-<CATEGORY>-<n>.
  'DETECT-',
  // Findings from the CLI's ConfigGuard (`opena2a guard`).
  'CONFIG-GUARD-',
]);

/** The CLI-owned prefix `id` begins with, or undefined when it begins with none. */
export function cliOwnedPrefixOf(id: string): string | undefined {
  return CLI_OWNED_ID_PREFIXES.find((prefix) => id.startsWith(prefix));
}
