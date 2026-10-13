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
 *
 * Both commands are now hidden from `--help`, and the docs cite neither
 * (__tests__/docs/documented-command-arguments.test.ts): the OpenClaw block
 * documents `secure ~/.openclaw`, which acts on `$HOME` only because the line
 * names it. The guard below stays so a reintroduced no-directory `--fix` line
 * fails here with the #526 reason.
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
  it('reads the directory argument of a documented --fix line (non-vacuity)', () => {
    expect(positionalsAfter('hackmyagent secure-openclaw --fix   # Auto-fix issues', 'secure-openclaw')).toEqual([]);
    expect(positionalsAfter('hackmyagent secure-openclaw ~/.openclaw --fix --dry-run', 'secure-openclaw')).toEqual(['~/.openclaw']);
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

  it('names the OpenClaw directory on every --fix line of the OpenClaw usage block', () => {
    const text = readFileSync(join(ROOT, 'docs', 'SECURITY_CHECKS.md'), 'utf8');
    expect(text).not.toMatch(/#\s*Scan default ~\/\.moltbot/);
    const section = text.slice(text.indexOf('## OpenClaw Security Checks'), text.indexOf('### SKILL Checks'));
    const fixLines = section.split('\n').filter(l => /^hackmyagent secure\b.*--fix\b/.test(l.split(/\s#/)[0]));
    expect(fixLines.length).toBeGreaterThan(0);
    expect(fixLines.filter(l => !(positionalsAfter(l, 'secure') ?? []).includes('~/.openclaw'))).toEqual([]);
  });
});
