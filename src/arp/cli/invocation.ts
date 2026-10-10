import * as path from 'path';

/**
 * The command line that reaches this program, for its help text and hints.
 *
 * The help used to print `arp-guard <command>` and the telemetry hints
 * `arp telemetry ...`, and neither name is a binary: the `arp-guard` package
 * declares no `bin`, hackmyagent's only `bin` is `hackmyagent`, and on macOS
 * `arp` is the system address-resolution tool. A reader who typed what the
 * help showed got "command not found" or a different program. `opena2a
 * runtime` is not a substitute to print here either: it is its own
 * implementation with start, status, tail and init, so `proxy`, `budget` and
 * `telemetry` are unknown subcommands there.
 *
 * So the help names the invocation the reader just ran, which exists by
 * construction:
 *  - launched as a script (`node .../dist/arp/cli/index.js`), it is that
 *    `node` line, with the path relative to the working directory when the
 *    script sits under it;
 *  - launched through a `bin` shim (no script extension), it is the shim's
 *    name when its directory is on PATH, so a binary declared later is picked
 *    up with no string edit, and the shim's full path when it is not.
 */
export function invocation(
  argv: readonly string[] = process.argv,
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): string {
  const script = path.resolve(cwd, argv[1] || path.join(__dirname, 'index.js'));

  if (/\.[cm]?[jt]s$/.test(script)) {
    const rel = path.relative(cwd, script);
    const shown = rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : script;
    // Running from source goes through tsx; plain `node` cannot load the
    // extensionless imports in this tree.
    const runner = /\.[cm]?ts$/.test(script) ? 'npx tsx' : 'node';
    return `${runner} ${shellWord(shown)}`;
  }

  const dir = path.dirname(script);
  const onPath = (env.PATH ?? '')
    .split(path.delimiter)
    .some((d) => d !== '' && path.resolve(cwd, d) === dir);
  return onPath ? shellWord(path.basename(script)) : shellWord(script);
}

/** Quote a path for a POSIX shell only when it needs it. */
function shellWord(s: string): string {
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}
