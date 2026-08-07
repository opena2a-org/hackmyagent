/**
 * Walker behind `__tests__/ui/printed-flag-citations.test.ts` (#372).
 *
 * Finds every CLI flag the tool prints at a user and says which command it
 * would have to be registered on. Kept here rather than inline in the suite so
 * the extraction can be probed on its own; `__tests__/helpers/**` is excluded
 * from the vitest include list, so this file is not itself a suite.
 *
 * Two measured constraints shaped it, both of which defeat the obvious
 * implementation:
 *
 *  1. **A `console.log(` grep is insufficient.** `fix-all`'s dead
 *     `--uninstall` citation lives in a template literal inside an array
 *     push, so a print-call grep never sees it. String literals are walked,
 *     and the print-call test is only used to decide whether a flag with no
 *     command named beside it is advice or incidental text.
 *
 *  2. **A global "does this flag exist anywhere" check is insufficient.**
 *     Only 4 of 23 printed flag tokens were unregistered anywhere in the
 *     tool. `--model` is registered on `attack` and `--uninstall` is
 *     registered elsewhere, so both pass a union check while being dead where
 *     they are printed. Attribution is per-command.
 */
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

export interface PrintedFlag {
  /** Repo-relative file. */
  file: string;
  /** 1-indexed line of the flag token. */
  line: number;
  /** The flag as printed, e.g. `--uninstall`. */
  flag: string;
  /**
   * Command the flag must be registered on, or `null` when the string names no
   * command and sits outside `src/cli.ts`, where there is no enclosing command
   * to attribute it to. A `null` target is checked against the union instead.
   */
  command: string | null;
  /** True when the command came from the enclosing registration, not the text. */
  inferred: boolean;
  /** The line, for the failure message. */
  text: string;
}

/**
 * Executables whose flags belong to them. A segment naming one of these is
 * quoting another tool's command line, not ours.
 *
 * `ai-trust` was on this list and came off with #432. Being on it made the
 * gate skip four printed lines — `ai-trust check <name> --scan-if-missing`,
 * `ai-trust audit <file> --scan-missing` — which were dead ends for every
 * reader: a dependency does not put its `bin` on a consumer's PATH, so the
 * suggestion never ran for anyone who installed only `hackmyagent`. Removing
 * the runtime dependency made that unambiguous, and the citations now name
 * `check` and `trust`, which this tool registers itself.
 *
 * The entries that remain are cited through a runner that does resolve them
 * (`npx opena2a-cli protect .`) or are genuinely another tool's command line.
 * Adding a name here suppresses a real class of defect, so it needs the same
 * justification: the reader can run it as printed.
 *
 * Program names that are also ordinary English words are deliberately NOT on
 * this list — `go`, `find`, `ls`, `ps`, `gh`, `az`, `ag`, `helm`. With them on
 * it, "If you go further, use `--x`" and "To find more, use `--x`" were both
 * skipped, so an advice line could hide a dead citation behind a common verb.
 * Measured: removing them turns those two cases red and leaves the tree at the
 * same 0 unregistered, so the coverage is strictly larger for no false
 * positives. Under-detection is the direction that matters here — a guard that
 * silently skips is indistinguishable from a guard that passes.
 */
const FOREIGN_EXECUTABLE =
  /\b(npm|npx|pnpm|yarn|pip|pip3|pipx|python|python3|node|deno|bun|cargo|git|curl|wget|docker|podman|kubectl|aws|gcloud|terraform|grep|rg|sed|awk|tar|unzip|ssh|scp|openssl|gpg|chmod|chown|snyk|semgrep|trivy|gitleaks|glab|brew|apt|apt-get|yum|dnf|jq|yq|shasum|sha256sum|systemctl|journalctl|arp-guard|opena2a|secretless|secretless-ai)\b/;

/** Call shapes whose string arguments reach a user. */
const PRINT_CALL =
  /(?:console\.(?:log|error|warn|info)|process\.(?:stdout|stderr)\.write|writeLargeStdout|writeJsonStdout|\.push|print[A-Za-z]*|render[A-Za-z]*|say|emit[A-Za-z]*)\s*\(\s*$/;

interface Literal {
  /** Literal body, quotes stripped. */
  body: string;
  /** Absolute offset of the literal body's first character. */
  start: number;
  /** Up to 80 characters of source immediately before the opening quote. */
  callee: string;
}

/**
 * Extract string literals, skipping comments. Deliberately a scanner and not a
 * regex: `--uninstall` sits in a template literal spanning an interpolation,
 * and the citation that started this class (`scan-soul --explain`) sat in a
 * multi-line one.
 */
export function stringLiterals(src: string): Literal[] {
  const out: Literal[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const next = src[i + 1];
    if (c === '/' && next === '/') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && next === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      const start = i + 1;
      let j = start;
      let depth = 0;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (quote === '`' && src[j] === '$' && src[j + 1] === '{') { depth++; j += 2; continue; }
        if (quote === '`' && depth > 0 && src[j] === '}') { depth--; j++; continue; }
        if (depth === 0 && src[j] === quote) break;
        if (quote !== '`' && src[j] === '\n') break; // unterminated; bail
        j++;
      }
      out.push({
        body: src.slice(start, j),
        start,
        callee: src.slice(Math.max(0, i - 80), i),
      });
      i = j + 1;
      continue;
    }
    i++;
  }
  return out;
}

export interface CommandRegion {
  /** The registered name, e.g. `status`. */
  name: string;
  /** Offset of the registration in the source. */
  idx: number;
  /**
   * The argv path that actually reaches it, e.g. `['nanomind', 'status']`.
   *
   * `nanomind status` and `nanomind setup` are registered on a SUB-program, so
   * `hackmyagent status --help` is not a command — and Commander answers it
   * with exit 0 and an empty body rather than an error, which is why a naive
   * `<name> --help` lookup returned an empty flag set for both and would have
   * passed every citation printed under them for the wrong reason.
   */
  path: string[];
}

/** `.command('name')` registrations in cli.ts, with their argv paths. */
export function commandRegions(cliSrc: string): CommandRegion[] {
  const raw: Array<{ name: string; idx: number; receiver: string; assignedTo?: string }> = [];
  // `[ \t]*\n?[ \t]*` rather than `\s*\n?\s*`: the latter is an ambiguous pair
  // (`\s` already matches `\n`), which backtracks quadratically on a long
  // whitespace run. This only ever reads our own source, so it is a hygiene
  // fix rather than a live hazard — but an ambiguous pattern that is fine
  // today is the one that gets copied to a path that reads input.
  const re = /(?:(?:const|let|var)[ \t]+(\w+)[ \t]*=[ \t]*)?(\w+)[ \t]*\n?[ \t]*\.command\('([^']+)'/g;
  for (const m of cliSrc.matchAll(re)) {
    raw.push({
      assignedTo: m[1],
      receiver: m[2],
      name: m[3].split(' ')[0],
      idx: m.index! + m[0].indexOf('.command('),
    });
  }
  // `const nanomindCmd = program.command('nanomind')` makes `nanomindCmd` the
  // handle for the `nanomind` command.
  const varToCommand = new Map<string, string>();
  for (const r of raw) if (r.assignedTo) varToCommand.set(r.assignedTo, r.name);

  return raw.map((r) => {
    const parent = varToCommand.get(r.receiver);
    return { name: r.name, idx: r.idx, path: parent ? [parent, r.name] : [r.name] };
  });
}

function enclosingCommand(marks: CommandRegion[], offset: number): string | null {
  let cur: string | null = null;
  for (const m of marks) {
    if (m.idx <= offset) cur = m.name;
    else break;
  }
  return cur;
}

/** Every `.ts` file under `dir`, excluding declaration files. */
function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...tsFiles(p));
    else if (e.name.endsWith('.ts') && !e.name.endsWith('.d.ts')) out.push(p);
  }
  return out;
}

/**
 * Subtrees that are not this CLI's printed output.
 *
 * `src/arp/` is a SEPARATE program (`arp-guard`) with its own flag set and its
 * own help; asserting its flags against hackmyagent's Commander registry would
 * be checking the wrong registry, not covering more ground.
 */
export const NOT_THIS_CLI = [path.join('src', 'arp')];

/** Walk one source file. Exported so the extraction can be tested on a plant. */
export function printedFlagsInSource(opts: {
  src: string;
  /** Repo-relative label used in `PrintedFlag.file`. */
  file: string;
  /** Commands the Commander program registers. */
  verbs: ReadonlySet<string>;
  /** `.command(…)` offsets, when this source is `src/cli.ts`. */
  marks?: CommandRegion[];
}): PrintedFlag[] {
  const { src, file: rel, verbs } = opts;
  const marks = opts.marks ?? [];
  const isCli = marks.length > 0;
  const found: PrintedFlag[] = [];
  {
    // Precomputed line index so a flag's offset maps to a line number.
    const lineStarts: number[] = [0];
    for (let k = 0; k < src.length; k++) if (src[k] === '\n') lineStarts.push(k + 1);
    const lineOf = (off: number) => {
      let lo = 0; let hi = lineStarts.length - 1;
      while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= off) lo = mid; else hi = mid - 1; }
      return lo;
    };

    for (const lit of stringLiterals(src)) {
      for (const fm of lit.body.matchAll(/(--[a-z][a-z0-9-]+)/g)) {
        const flag = fm[1];
        const at = fm.index!;
        const before = lit.body.slice(0, at);
        const after = lit.body.slice(at + flag.length);
        // CSS custom property, not a CLI flag: `var(--x)` or an `--x:` declaration.
        if (/var\(\s*$/.test(before) || /^\s*:/.test(after)) continue;
        // The invocation this flag belongs to: text back to the nearest
        // sentence, quote or newline boundary.
        // A sentence boundary needs a word character before the period. The
        // first spelling split on any `. `, which broke the commonest citation
        // shape in this tree — `${CLI_PREFIX} secure . --fix`, where the `.`
        // is the target — and silently dropped the command from every one of
        // them. Under-attribution is the dangerous direction here: it turns a
        // per-command assertion back into the union check that #372 measured
        // as insufficient.
        const segment = before.split(/[`'"\n]|(?<=[A-Za-z0-9)])\.\s|;\s|\|\s/).pop() ?? before;
        if (FOREIGN_EXECUTABLE.test(segment)) continue;

        // An explicitly named command wins over the enclosing registration.
        let command: string | null = null;
        const explicit = [...segment.matchAll(
          /(?:hackmyagent|hma|\$\{CLI_PREFIX\}|\$\{prefix\}|\$\{getCheckCommand\(\)\}|\$\{getSecureCommand\(\)\})\s+([a-z][a-z0-9-]+)/g,
        )].pop();
        if (explicit && verbs.has(explicit[1])) command = explicit[1];
        if (!command) {
          // Bare backticked invocation: `scan-soul --explain`. The segment
          // boundary is the backtick, so the verb is the WHOLE segment. A
          // looser "last word is a known verb" rule reads prose — "loaded
          // from secure, immutable sources" — as an invocation of `secure`,
          // which is how the first draft attributed 24 lines of OASB
          // remediation text to the wrong command.
          const trimmed = segment.trim();
          if (verbs.has(trimmed)) command = trimmed;
        }
        const inferred = command === null;
        if (inferred) {
          // No command named. Only treat it as advice about our own CLI when
          // the string is one we print; otherwise it is incidental prose.
          if (!PRINT_CALL.test(lit.callee)) continue;
          if (isCli) command = enclosingCommand(marks, lit.start + at);
        }

        const lineIdx = lineOf(lit.start + at);
        found.push({
          file: rel,
          line: lineIdx + 1,
          flag,
          command,
          inferred,
          text: src.slice(lineStarts[lineIdx], lineStarts[lineIdx + 1] ?? src.length).trim().slice(0, 160),
        });
      }
    }
  }
  return found;
}

/** Every `.md` file under `dir`, excluding anything generated or vendored. */
function markdownFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...markdownFiles(p));
    else if (e.name.endsWith('.md')) out.push(p);
  }
  return out;
}

/**
 * Walk one markdown file for flags cited against this CLI.
 *
 * #434 — `docs/use-cases/openclaw-security.md:61` showed a sample report whose
 * `Fix:` line cited `hackmyagent check --sign`, an option `check` does not
 * register. #372's gate did not miss it: that gate's scope is string literals
 * in `src/`, and the scope was accurate. Markdown has no string literals, so
 * the same class of dead citation lives in a file no walker read.
 *
 * This is the widening #432 already made for the executable skip list, applied
 * to the file set: the fix worth making closes the class, not the instance.
 *
 * Only code — fenced blocks and inline spans — is read. Prose that happens to
 * contain a hyphenated phrase is not an invocation, and reading it would
 * reproduce the "loaded from secure, immutable sources" misattribution that
 * the segment rule above exists to prevent.
 */
export function printedFlagsInMarkdown(opts: {
  src: string;
  file: string;
  verbs: ReadonlySet<string>;
}): PrintedFlag[] {
  const { src, file: rel, verbs } = opts;
  const found: PrintedFlag[] = [];

  const lineStarts: number[] = [0];
  for (let k = 0; k < src.length; k++) if (src[k] === '\n') lineStarts.push(k + 1);
  const lineOf = (off: number) => {
    let lo = 0; let hi = lineStarts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= off) lo = mid; else hi = mid - 1; }
    return lo;
  };

  // Code regions: fenced blocks, then inline spans. Offsets are kept so a
  // finding reports the line the reader would open.
  const regions: Array<{ body: string; start: number }> = [];
  for (const m of src.matchAll(/```[^\n]*\n([\s\S]*?)```/g)) {
    regions.push({ body: m[1], start: m.index! + m[0].indexOf('\n') + 1 });
  }
  for (const m of src.matchAll(/`([^`\n]+)`/g)) {
    regions.push({ body: m[1], start: m.index! + 1 });
  }

  for (const region of regions) {
    // One invocation per line: a fenced block holds many, and flags must not
    // leak across them the way they would if the whole block were one segment.
    let cursor = 0;
    for (const rawLine of region.body.split('\n')) {
      const lineStart = region.start + cursor;
      cursor += rawLine.length + 1;

      // Strip a shell prompt so `$ hackmyagent check --json` reads the same as
      // the bare form.
      const line = rawLine.replace(/^\s*\$\s*/, '');
      const invocation = /(?:^|[\s|;&(])(?:hackmyagent|hma|npx\s+hackmyagent)\s+([a-z][a-z0-9-]*)/.exec(line);
      if (!invocation) continue;
      const verb = invocation[1];
      if (!verbs.has(verb)) continue;

      // Flags after the verb only. A flag before it belongs to another program
      // in a pipeline.
      const tail = line.slice(invocation.index + invocation[0].length);
      for (const fm of tail.matchAll(/(?:^|\s)(--[a-z][a-z0-9-]+)/g)) {
        const at = invocation.index + invocation[0].length + fm.index! + fm[0].indexOf('--');
        const lineIdx = lineOf(lineStart + at);
        found.push({
          file: rel,
          line: lineIdx + 1,
          flag: fm[1],
          command: verb,
          inferred: false,
          text: src.slice(lineStarts[lineIdx], lineStarts[lineIdx + 1] ?? src.length).trim().slice(0, 160),
        });
      }
    }
  }
  return found;
}

export function collectPrintedFlags(opts: {
  repoRoot: string;
  /** Commands the Commander program registers. */
  verbs: ReadonlySet<string>;
}): PrintedFlag[] {
  const { repoRoot, verbs } = opts;
  const srcRoot = path.join(repoRoot, 'src');
  const cliRel = path.join('src', 'cli.ts');
  const marks = commandRegions(readFileSync(path.join(repoRoot, cliRel), 'utf8'));

  const found: PrintedFlag[] = [];
  for (const file of tsFiles(srcRoot)) {
    const rel = path.relative(repoRoot, file);
    if (NOT_THIS_CLI.some((d) => rel.startsWith(d))) continue;
    found.push(...printedFlagsInSource({
      src: readFileSync(file, 'utf8'),
      file: rel,
      verbs,
      marks: rel === cliRel ? marks : undefined,
    }));
  }
  found.push(...collectMarkdownFlags(opts));
  return found;
}

/**
 * The documentation half of the same walk: `README.md` and everything under
 * `docs/`. Separate entry point so a suite can report the two scopes apart
 * while the assertion over them stays one rule (#434).
 */
export function collectMarkdownFlags(opts: {
  repoRoot: string;
  verbs: ReadonlySet<string>;
}): PrintedFlag[] {
  const { repoRoot, verbs } = opts;
  const files: string[] = [];
  const readme = path.join(repoRoot, 'README.md');
  try { readFileSync(readme); files.push(readme); } catch { /* no README */ }
  try { files.push(...markdownFiles(path.join(repoRoot, 'docs'))); } catch { /* no docs/ */ }

  const found: PrintedFlag[] = [];
  for (const file of files) {
    found.push(...printedFlagsInMarkdown({
      src: readFileSync(file, 'utf8'),
      file: path.relative(repoRoot, file),
      verbs,
    }));
  }
  return found;
}
