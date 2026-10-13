/**
 * Reads VHS tapes (`docs/**\/*.tape`): what a tape types on screen, what it
 * types inside a `Hide`..`Show` block, and the settings it declares.
 *
 * A tape is the script a recording is rendered from, so the lines it types
 * are documented commands like any other: the gates under `__tests__/docs/`
 * hold them to the CLI's registry and to the recording's sidecar.
 */
import { readdirSync, statSync } from 'node:fs';
import * as path from 'node:path';

export interface Tape {
  /** `Type` strings outside every `Hide`..`Show` block, in order: what the recording shows being typed. */
  typed: string[];
  /** `Type` strings inside a `Hide`..`Show` block: setup the recording does not show. */
  hidden: string[];
  /** `Require` operands: the binaries the tape refuses to start without. */
  requires: string[];
  /** `Set <name> <value>`, quotes removed. */
  settings: Map<string, string>;
  /** `Output` paths. */
  outputs: string[];
  /** `Screenshot` paths: the held frames written beside the recording. */
  screenshots: string[];
  /** Every non-comment line, trimmed. */
  lines: string[];
}

const QUOTED = /^(["'`])(.*)\1$/;

function unquote(value: string): string {
  const m = value.match(QUOTED);
  return m ? m[2] : value;
}

/**
 * A `Type` line this parser cannot read throws: a typed line that is skipped
 * is a typed line no gate checks.
 */
export function parseTape(src: string): Tape {
  const tape: Tape = { typed: [], hidden: [], requires: [], settings: new Map(), outputs: [], screenshots: [], lines: [] };
  let hidden = false;
  for (const raw of src.split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    tape.lines.push(line);
    const [command, ...rest] = line.split(/\s+/);
    const operand = line.slice(command.length).trim();
    if (command === 'Hide') hidden = true;
    else if (command === 'Show') hidden = false;
    else if (/^Type(@\S+)?$/.test(command)) {
      const m = operand.match(QUOTED);
      if (!m) throw new Error(`unreadable Type line in a tape: ${line}`);
      (hidden ? tape.hidden : tape.typed).push(m[2]);
    } else if (command === 'Require') tape.requires.push(operand);
    else if (command === 'Output') tape.outputs.push(operand);
    else if (command === 'Screenshot') tape.screenshots.push(operand);
    else if (command === 'Set') tape.settings.set(rest[0], unquote(rest.slice(1).join(' ')));
  }
  return tape;
}

/** Every `.tape` file under `dir`, sorted. */
export function tapeFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...tapeFiles(p));
    else if (name.endsWith('.tape')) out.push(p);
  }
  return out;
}
