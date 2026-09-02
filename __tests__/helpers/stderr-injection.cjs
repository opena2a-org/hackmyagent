/**
 * HMA-28 stderr-injection arm.
 *
 * Loaded via `NODE_OPTIONS="--require <abs path to this file>"`, it writes one
 * line to stderr from every node process that starts while the variable is set
 * — including every `dist/cli.js` the spawn harnesses run. That reproduces the
 * measured pass-21 failure mechanism: on a saturated machine some process in
 * the chain emits a stray stderr byte, and any harness that JSON.parses a
 * merged stdout+stderr stream throws on the trailing garbage.
 *
 * Usage (red at the pre-fix harnesses, green after HMA-28):
 *
 *   NODE_OPTIONS="--require $PWD/__tests__/helpers/stderr-injection.cjs" \
 *     npx vitest run __tests__/repo/obstruction-disclosure.test.ts \
 *       __tests__/cli/secure-unread-input-gate.test.ts \
 *       __tests__/cli/secure-unread-directory-gate.test.ts
 *
 * The line deliberately contains no `{` so it can never masquerade as the
 * start of a JSON body, and no token any text assertion in those suites looks
 * for. `__tests__/repo/hma-28-stdout-only-parse.test.ts` exercises this module
 * directly.
 */
process.stderr.write('hma-28 injected stderr line\n');
