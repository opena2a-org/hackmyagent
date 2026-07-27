/**
 * Gate for the `Scanned with hackmyagent vX.Y.Z` footer (#202).
 *
 * The footer is a human-readable trailer, so it may only ever reach a
 * human-readable stream. #202 shipped it gated on `--json` alone:
 *
 *   if (VERSION_FOOTER_COMMANDS.has(cmd) && !ciMode && !opts().json)
 *
 * `secure` also accepts `-f, --format <text|json|sarif|html|asp|asff>`, and
 * documents `--json` as *deprecated in favour of `--format json`*. So the
 * deprecated path was protected and every recommended one was not: the
 * footer was appended after the closing brace of the document.
 *
 * (`scan-soul` and `detect` declare only `--json`, no `--format`. The gate
 * below is written against the resolved format anyway, so it stays correct
 * if either grows one.)
 *
 *   $ hackmyagent secure <dir> --format sarif
 *     ...
 *     }
 *     Scanned with hackmyagent v0.25.1     <- JSON.parse fails here
 *
 * That breaks `--format json` for any scripted consumer and breaks SARIF
 * upload to the GitHub Security tab, which is the entire point of the SARIF
 * writer. The version is already carried inside those payloads as the
 * top-level `hackmyagentVersion` field, so suppressing the trailer loses
 * nothing.
 *
 * The rule is therefore about the *resolved* format, not about one flag:
 * emit only when the command is rendering text for a person.
 */

/** Commands that close with the version footer. */
export const VERSION_FOOTER_COMMANDS: ReadonlySet<string> = new Set([
  'secure',
  'detect',
  'scan-soul',
]);

export interface VersionFooterContext {
  /** Commander's resolved command name. */
  command: string;
  /** Global `--ci` mode: output must stay byte-stable for the corpus harness. */
  ciMode: boolean;
  /** The deprecated `--json` alias. */
  json?: boolean;
  /** `-f, --format <format>`. Absent or 'text' means human-readable. */
  format?: string;
}

/**
 * Resolve the effective output format, mirroring the `--json`-is-an-alias
 * rule `secure` applies at its action site (`options.json ? 'json' :
 * (options.format || 'text')`). Unknown values are returned as given: they
 * are rejected downstream, and treating an unrecognised format as text would
 * put the trailer back into whatever a future writer emits.
 */
export function resolveOutputFormat(opts: { json?: boolean; format?: string }): string {
  if (opts.json) return 'json';
  return opts.format || 'text';
}

/**
 * Whether the version footer may be printed for this invocation.
 *
 * Deliberately allow-list, not deny-list: only an explicitly textual render
 * qualifies. A new machine format added later is suppressed by default
 * rather than silently corrupted, which is the failure this function exists
 * to prevent.
 */
export function shouldPrintVersionFooter(ctx: VersionFooterContext): boolean {
  if (!VERSION_FOOTER_COMMANDS.has(ctx.command)) return false;
  if (ctx.ciMode) return false;
  return resolveOutputFormat(ctx) === 'text';
}
