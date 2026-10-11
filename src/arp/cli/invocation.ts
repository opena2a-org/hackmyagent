import * as path from 'path';
import { fs } from '../../hardening/tracked-fs';

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
 *  - launched as a script (`node .../dist/arp/cli/index.js`, or the same path
 *    without its extension, or its directory, both of which Node completes to
 *    index.js), it is that `node` line, with the path relative to the working
 *    directory when the script sits under it;
 *  - launched through a `bin` shim (a file at exactly the path that was run,
 *    with no script extension), it is the shim's name when its directory is on
 *    PATH, so a binary declared later is picked up with no string edit, and the
 *    shim's full path when it is not.
 *
 * `argv[0]` cannot tell the two apart: a shim's `#!/usr/bin/env node` line
 * makes it the node binary as well.
 *
 * Asynchronous because telling a completed path from a shim asks the
 * filesystem, and this tree's filesystem namespace is promise-based.
 */
export async function invocation(
  argv: readonly string[] = process.argv,
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
  platform: NodeJS.Platform = process.platform,
): Promise<string> {
  const p = platform === 'win32' ? path.win32 : path.posix;
  const script = p.resolve(cwd, argv[1] || p.join(__dirname, 'index.js'));

  const entry = /\.[cm]?[jt]s$/.test(script) ? script : await completedEntry(script, p);
  if (entry) {
    const rel = p.relative(cwd, script);
    const shown = rel && !rel.startsWith('..') && !p.isAbsolute(rel) ? rel : script;
    // Running from source goes through tsx; plain `node` cannot load the
    // extensionless imports in this tree.
    const runner = /\.[cm]?ts$/.test(entry) ? 'npx tsx' : 'node';
    return `${runner} ${shellWord(shown, platform)}`;
  }

  const dir = p.dirname(script);
  const onPath = (env.PATH ?? '')
    .split(p.delimiter)
    .some((d) => d !== '' && p.resolve(cwd, d) === dir);
  return shellWord(onPath ? p.basename(script) : script, platform);
}

/**
 * The file Node loaded for a script path given without its extension:
 * `node dist/arp/cli` runs the directory's index.js and `node dist/arp/cli/index`
 * runs index.js beside it, while `process.argv[1]` keeps the path as typed.
 * For a directory that is its index.js or index.ts; for any other path that is
 * not a file, including one that names nothing on disk such as
 * `dist/arp/cli/index`, the path with `.js` or `.ts` appended. Undefined when
 * the path is itself a file, which is how a bin shim arrives, or when no such
 * completed file exists.
 */
async function completedEntry(script: string, p: path.PlatformPath): Promise<string | undefined> {
  const st = await statIfPresent(script);
  if (st?.isFile()) return undefined;
  const base = st?.isDirectory() ? p.join(script, 'index') : script;
  for (const ext of ['.js', '.ts']) {
    if ((await statIfPresent(base + ext))?.isFile()) return base + ext;
  }
  return undefined;
}

/** A path's stat, or undefined when it names nothing this process can stat. */
function statIfPresent(file: string) {
  return fs.stat(file).catch(() => undefined);
}

/**
 * A path as one shell word. On POSIX it is printed bare when it holds only
 * ASCII letters, digits and `_ @ % + = : , . / -`, and otherwise in single
 * quotes, each embedded single quote closed, escaped and reopened. On Windows
 * it is printed bare when it holds only ASCII letters, digits and
 * `_ @ + = : , . \ / -`, and otherwise in double quotes, a character no
 * Windows path can contain; so a space, `~`, `(` or a non-ASCII letter is
 * quoted. Double quotes keep the path one word in cmd.exe and PowerShell, but
 * PowerShell still expands `$` and the backtick inside them, and cmd.exe still
 * expands `%NAME%`.
 */
function shellWord(s: string, platform: NodeJS.Platform): string {
  if (platform === 'win32') return /^[\w@+=:,.\\/-]+$/.test(s) ? s : `"${s}"`;
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}
