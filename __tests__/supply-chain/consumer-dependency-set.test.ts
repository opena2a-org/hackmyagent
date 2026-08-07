/**
 * #432 — invariants behind the consumer-resolution gate, checked offline.
 *
 * `scripts/audit-consumer-resolution.mjs` is the real gate, but it resolves a
 * tree against the live registry, so it lives in CI and not in `npm test`. If
 * that were the only check, the dependency edge this issue removed could come
 * back in a PR and nothing on a developer's machine would say so until CI ran.
 *
 * These pin the parts that need no network. Every one of them fails on
 * `6c48698` (0.26.1), which is the shape the fix has to have.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const pkg = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));

/**
 * `ai-trust` depends back on `hackmyagent`, so declaring it in any dependency
 * field resolves a second, nine-month-old copy of this tool into every
 * consumer's tree — with its own deprecation notice as the first screen after
 * install — and drags `onnxruntime-node -> adm-zip` in a second time.
 *
 * HackMyAgent is standalone. The capability a reader would have reached for
 * `ai-trust` to get is served by this tool's own `trust` and `check`.
 */
describe('#432 the ai-trust edge stays removed', () => {
  const FIELDS = [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ] as const;

  for (const field of FIELDS) {
    it(`does not declare ai-trust in ${field}`, () => {
      expect(Object.keys(pkg[field] ?? {})).not.toContain('ai-trust');
    });
  }

  it('does not resolve ai-trust anywhere in the committed lockfile', () => {
    const lock = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package-lock.json'), 'utf8'));
    const entries = Object.keys(lock.packages ?? {}).filter((p) =>
      p.split('node_modules/').pop() === 'ai-trust'
    );
    expect(entries, `ai-trust is back in the lockfile at: ${entries.join(', ')}`).toEqual([]);
  });

  it('resolves no second copy of hackmyagent in the committed lockfile', () => {
    const lock = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package-lock.json'), 'utf8'));
    const nested = Object.keys(lock.packages ?? {}).filter(
      (p) => p !== '' && p.endsWith('node_modules/hackmyagent')
    );
    expect(nested, `nested hackmyagent copies: ${nested.join(', ')}`).toEqual([]);
  });
});

/**
 * The four lines that sent a reader to another CLI. A dependency does not put
 * its `bin` on a consumer's PATH, so `ai-trust check <name> --scan-if-missing`
 * never ran for anyone who installed only `hackmyagent` — it was a dead end
 * before the edge was removed, and an obvious one after.
 *
 * Source strings, not `console.log` calls: the citations lived inside array
 * pushes and template literals, which a print-call grep does not see. That is
 * the same constraint `__tests__/helpers/printed-flag-citations.ts` documents.
 */
describe('#432 no printed string sends the reader to the ai-trust CLI', () => {
  function sourceFiles(dir: string): string[] {
    return readdirSync(dir).flatMap((entry) => {
      const full = path.join(dir, entry);
      if (statSync(full).isDirectory()) return sourceFiles(full);
      return full.endsWith('.ts') ? [full] : [];
    });
  }

  it('cites no ai-trust subcommand in src/', () => {
    // A comment may still discuss the tool; a printed line may not invoke it.
    // Matches `ai-trust <verb>` only, so prose naming the project is untouched.
    const INVOCATION = /\bai-trust\s+(?:check|audit|scan|trust|verify)\b/;

    const offenders: string[] = [];
    for (const file of sourceFiles(path.join(REPO_ROOT, 'src'))) {
      const lines = readFileSync(file, 'utf8').split('\n');
      lines.forEach((line, i) => {
        if (!INVOCATION.test(line)) return;
        // Strip the comment forms this file uses before judging.
        const code = line.replace(/^\s*(?:\/\/|\*|\/\*).*$/, '');
        if (!INVOCATION.test(code)) return;
        offenders.push(`${path.relative(REPO_ROOT, file)}:${i + 1}: ${line.trim()}`);
      });
    }

    expect(
      offenders,
      `these lines tell a reader to run a CLI that installing hackmyagent does ` +
        `not give them:\n${offenders.join('\n')}`
    ).toEqual([]);
  });
});

describe('#432 the consumer-resolution gate stays wired', () => {
  it('exposes the gate as an npm script', () => {
    expect(pkg.scripts?.['audit:consumer']).toBe('node scripts/audit-consumer-resolution.mjs');
  });

  it('runs that script from the dependency-audit workflow', () => {
    const wf = readFileSync(
      path.join(REPO_ROOT, '.github', 'workflows', 'dependency-audit.yml'),
      'utf8'
    );
    expect(wf).toContain('npm run audit:consumer');
  });

  /**
   * The reason this gate exists at all. If a future edit "simplifies" the
   * script into auditing the repo's own lockfile, it becomes a duplicate of
   * the job above it and the blind spot returns silently.
   */
  it('resolves a packed tarball rather than this repo lockfile', () => {
    const script = readFileSync(
      path.join(REPO_ROOT, 'scripts', 'audit-consumer-resolution.mjs'),
      'utf8'
    );
    expect(script).toContain('npm');
    expect(script).toContain('pack');
    expect(script).toContain('--ignore-scripts');
    expect(script).toContain('--package-lock-only');
  });
});
