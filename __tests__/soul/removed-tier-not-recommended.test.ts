/**
 * A tier we removed must not still be recommended by the text.
 *
 * 0.29.0 removes the `claude --print` tier from `scan-soul --deep`, but the
 * message shown when the deep tier is unavailable still read "set
 * ANTHROPIC_API_KEY or install the claude CLI". Installing it would have done
 * nothing, so the one line a blocked user reads sent them somewhere that could
 * not help — the dead-end shape the repo already rejects for finding-fix text.
 *
 * This asserts the property rather than the sentence: no user-facing string may
 * offer the local `claude` binary as a way to obtain deep analysis. Matching on
 * the removal's MECHANISM (recommending an install of `claude`) rather than on
 * the exact wording, so a reworded version of the same advice still fails.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const SRC = path.join(__dirname, '..', '..', 'src');

function userFacingLines(file: string): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  readFileSync(path.join(SRC, file), 'utf8').split('\n').forEach((text, i) => {
    const trimmed = text.trim();
    // Comments explain the removal on purpose; only what we PRINT is in scope.
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
    out.push({ line: i + 1, text });
  });
  return out;
}

describe('#463/0.29.0 the removed claude --print tier is not offered as a remedy', () => {
  it('no printed string tells the user to install or use the claude CLI for deep analysis', () => {
    const offenders: string[] = [];
    for (const file of ['cli.ts', 'soul/scanner.ts']) {
      for (const { line, text } of userFacingLines(file)) {
        // "install the claude CLI", "install claude", "use the claude CLI", etc.
        if (/\b(install|use|run)\b[^\n]{0,24}\bclaude\b(?![-.\w])/i.test(text)) {
          offenders.push(`${file}:${line}: ${text.trim().slice(0, 110)}`);
        }
      }
    }
    expect(offenders, `a removed tier is still being recommended:\n${offenders.join('\n')}`).toEqual([]);
  });

  it('the deep-unavailable message still names the mechanism that DOES work', () => {
    // The complement: having removed the dead advice, the line must not become
    // a bare "unavailable" with no way forward.
    const cli = readFileSync(path.join(SRC, 'cli.ts'), 'utf8');
    const message = cli.split('\n').find((l) => l.includes('Deep analysis unavailable'));
    expect(message, 'the deep-unavailable message disappeared entirely').toBeTruthy();
    expect(message!).toMatch(/ANTHROPIC_API_KEY/);
  });
});
