/**
 * Decides, on the parsed shell command, whether a line writes to a hardcoded
 * /tmp/ path (NEMO-006, CWE-377).
 *
 * A /tmp/ literal counts only in a write position: the target of a redirect
 * (`> /tmp/x`, `>> /tmp/x`), an operand of a command that creates or writes
 * files (mkdir, touch, cp, mv, tee, install, ln), or the value of an output
 * flag (`-o /tmp/x`). A /tmp/ literal inside a quoted argument to any other
 * command (`echo "/tmp/x"`, a test fixture string) is data, not a write, and a
 * `>` inside quotes is not a redirect.
 *
 * One pass over the line, linear in its length.
 */

interface Word {
  text: string;
  /** Some part of the word was quoted or escaped. */
  quoted: boolean;
}

type Item =
  | { kind: 'word'; word: Word }
  | { kind: 'redirect'; write: boolean }
  | { kind: 'separator' };

const WRITE_COMMANDS = new Set(['mkdir', 'touch', 'cp', 'mv', 'tee', 'install', 'ln']);
const WRAPPER_COMMANDS = new Set(['sudo', 'command', 'exec', 'env', 'nohup', 'time', 'nice', 'doas']);
const OUTPUT_FLAGS = new Set(['-o', '-O', '--output', '--output-document']);

function tokenize(line: string): Item[] {
  const items: Item[] = [];
  let text = '';
  let quoted = false;
  let inWord = false;
  const flush = (): void => {
    if (inWord) items.push({ kind: 'word', word: { text, quoted } });
    text = '';
    quoted = false;
    inWord = false;
  };
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === '\\') {
      inWord = true;
      quoted = true;
      if (i + 1 < line.length) text += line[i + 1];
      i += 2;
    } else if (c === "'") {
      inWord = true;
      quoted = true;
      const end = line.indexOf("'", i + 1);
      const stop = end === -1 ? line.length : end;
      text += line.slice(i + 1, stop);
      i = stop + 1;
    } else if (c === '"') {
      inWord = true;
      quoted = true;
      i++;
      while (i < line.length && line[i] !== '"') {
        if (line[i] === '\\' && i + 1 < line.length) i++;
        text += line[i];
        i++;
      }
      i++;
    } else if (c === ' ' || c === '\t' || c === '\r') {
      flush();
      i++;
    } else if (c === '#' && !inWord) {
      break; // comment
    } else if (c === ';' || c === '|' || c === '&' || c === '(' || c === ')' || c === '\n') {
      // `&>` and `>&` are redirects; `&&`, `||`, `|&`, `;`, `&` end the command.
      if (c === '&' && line[i + 1] === '>') {
        flush();
        i += 2;
        if (line[i] === '>') i++;
        items.push({ kind: 'redirect', write: true });
        continue;
      }
      flush();
      items.push({ kind: 'separator' });
      i++;
    } else if (c === '>') {
      flush();
      i++;
      if (line[i] === '>' || line[i] === '|') i++;
      if (line[i] === '&') {
        // `>&2` duplicates a descriptor; it names no file.
        i++;
        items.push({ kind: 'redirect', write: false });
      } else {
        items.push({ kind: 'redirect', write: true });
      }
    } else if (c === '<') {
      flush();
      i++;
      while (line[i] === '<' || line[i] === '&') i++;
      items.push({ kind: 'redirect', write: false });
    } else {
      inWord = true;
      text += c;
      i++;
    }
  }
  flush();
  return items;
}

const isTmpPath = (word: Word): boolean => word.text.startsWith('/tmp/');

/** True when the line writes to a hardcoded /tmp/ path in a write position. */
export function shellLineWritesToTmp(line: string): boolean {
  const items = tokenize(line);
  let command: string | undefined; // basename of the command being read, once found
  let pendingRedirect: boolean | undefined; // the next word is a redirect target; true if it is written
  let previous: Word | undefined;

  for (const item of items) {
    if (item.kind === 'separator') {
      command = undefined;
      pendingRedirect = undefined;
      previous = undefined;
      continue;
    }
    if (item.kind === 'redirect') {
      pendingRedirect = item.write;
      continue;
    }
    const word = item.word;
    if (pendingRedirect !== undefined) {
      if (pendingRedirect && isTmpPath(word)) return true;
      pendingRedirect = undefined;
      continue;
    }
    if (command === undefined) {
      // Leading VAR=value assignments and wrappers (sudo, env, ...) precede the command.
      if (!word.quoted && /^[A-Za-z_][A-Za-z0-9_]*=/.test(word.text)) continue;
      const name = word.text.slice(word.text.lastIndexOf('/') + 1);
      if (WRAPPER_COMMANDS.has(name)) continue;
      command = name;
      previous = undefined;
      continue;
    }
    if (isTmpPath(word)) {
      if (WRITE_COMMANDS.has(command)) return true;
      // `-o /tmp/x` writes whatever the command is; a quoted path is only
      // trusted as an output when the command is a downloader.
      const outputFlag = previous !== undefined && !previous.quoted && OUTPUT_FLAGS.has(previous.text);
      if (outputFlag && (!word.quoted || command === 'curl' || command === 'wget')) return true;
    }
    previous = word;
  }
  return false;
}
