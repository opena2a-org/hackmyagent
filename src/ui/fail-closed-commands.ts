/**
 * Commands cli.ts prints only after a network call, built here so a test can
 * read them without one.
 *
 * Each operand the reader supplies is written `"${NAME:?set NAME to ...}"`.
 * A printed `<placeholder>` is shell syntax when pasted: `sha256sum <artifact>`
 * is a syntax error, and `docker exec <sandbox-container> npx ...` redirects
 * stdin from a file named `sandbox-container`, truncates a file named `npx`
 * and runs a different command. The fail-closed form makes bash, zsh and dash
 * stop with the message when NAME is unset, before the command runs, and pass
 * the value as one argument when it is set. The operand is literal text, never
 * an interpolated value, and its message holds only letters, digits, spaces
 * and `, . : / _ -`, so nothing in it is expanded.
 *
 * Angle brackets stay in usage syntax and in prose that is not a command.
 */

/** The `check` next-steps default for a full audit, when HMA_FULL_SCAN_HINT is unset. */
export function fullScanCommand(prefix: string): string {
  return `${prefix} secure "\${DIR:?set DIR to the project directory to audit}"`;
}

/** The `attack` run the `wild` report points to for testing an agent. */
export function wildAttackCommand(prefix: string): string {
  return `${prefix} attack "\${ENDPOINT:?set ENDPOINT to the URL of your agent API}" --model "\${MODEL:?set MODEL to the model name your agent calls}"`;
}

/** The `mark-stub` call the `pull-stubs` list ends with. */
export function markStubNextStep(prefix: string): string {
  return `${prefix} mark-stub "\${STUB_ID:?set STUB_ID to a Stub ID from the list above}" "\${STATUS:?set STATUS to the status to record, for example reviewed}" (add --dry-run to preview it)`;
}
