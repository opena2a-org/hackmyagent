/**
 * #526 — no document shows a `--fix` for a command whose default target is a
 * directory in the user's home folder without naming the directory.
 *
 * `docs/SECURITY_CHECKS.md` documented `hackmyagent secure-openclaw` as
 * scanning "default ~/.moltbot", and its next line was `hackmyagent
 * secure-openclaw --fix` with no directory. The real default is the first of
 * `~/.openclaw`, `~/.moltbot`, `~/.clawdbot` that exists, so running the two
 * lines verbatim during a release walkthrough rewrote 250 real `SKILL.md`
 * files under `~/.openclaw` (restored with `rollback`).
 *
 * `secure-openclaw` and `secure-nemoclaw` are the commands whose no-argument
 * form resolves to a directory under $HOME. `secure --fix` defaults to the
 * current project, which is where a reader running it expects it to act.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = join(__dirname, '..', '..');
const HOME_DEFAULT_COMMANDS = ['secure-openclaw', 'secure-nemoclaw'];

function markdownFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...markdownFiles(p));
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}

/** Positional arguments after `<command>` on a documented command line, comments stripped. */
function positionalsAfter(line: string, command: string): string[] | null {
  const at = line.indexOf(`hackmyagent ${command}`);
  if (at === -1) return null;
  const rest = line.slice(at + `hackmyagent ${command}`.length).split(/\s#/)[0].replace(/`.*$/, '');
  return rest.trim().split(/\s+/).filter(t => t && !t.startsWith('-'));
}

const docs = [join(ROOT, 'README.md'), ...markdownFiles(join(ROOT, 'docs'))];

describe('#526 --fix examples for $HOME-default commands name their directory', () => {
  it('finds the documented secure-openclaw examples (non-vacuity)', () => {
    const text = readFileSync(join(ROOT, 'docs', 'SECURITY_CHECKS.md'), 'utf8');
    expect(text.split('\n').filter(l => /hackmyagent secure-openclaw .*--fix/.test(l)).length).toBeGreaterThan(0);
  });

  it('never shows --fix without a directory argument', () => {
    const offenders: string[] = [];
    for (const file of docs) {
      readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
        for (const command of HOME_DEFAULT_COMMANDS) {
          const positionals = positionalsAfter(line, command);
          if (positionals === null || !/--fix\b/.test(line.split(/\s#/)[0])) continue;
          if (positionals.length === 0) offenders.push(`${relative(ROOT, file)}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    expect(offenders).toEqual([]);
  });

  it('states the real default directory order', () => {
    const text = readFileSync(join(ROOT, 'docs', 'SECURITY_CHECKS.md'), 'utf8');
    expect(text).not.toMatch(/secure-openclaw\s+#\s*Scan default ~\/\.moltbot/);
    expect(text).toContain('the first of ~/.openclaw, ~/.moltbot, ~/.clawdbot that exists');
  });
});
