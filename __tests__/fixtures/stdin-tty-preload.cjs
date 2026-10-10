/**
 * Makes the spawned CLI read its standard input as an interactive terminal.
 *
 * `check <URL>` shares a scan with the registry only when `process.stdin.isTTY`
 * is true (and `--ci` is off). A spawned child's standard input is a pipe or
 * /dev/null, where `isTTY` is undefined, so a spawn test cannot reach that
 * path without this. Loaded with `node --require <this file>`.
 */
Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
