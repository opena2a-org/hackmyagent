/**
 * #762 — documented commands whose flags are registered can still fail on
 * their ARGUMENTS. docs/REGISTRY_INTEGRATION.md passed the printed-flag gate
 * for its `--intensity` and `secure` lines while every one of them failed:
 *
 *  - `attack --intensity high` / `medium`: "Invalid intensity 'medium'. Use:
 *    passive, active, aggressive".
 *  - `secure @modelcontextprotocol/server-filesystem`: `secure` takes a
 *    directory ("Directory ... does not exist"); `check` takes packages.
 *  - `--registry-url https://registry.opena2a.org`: the host does not resolve;
 *    the CLI default is https://api.oa2a.org.
 *  - `attack --local --registry-report`: a --local run contacts no agent and
 *    is never reported, so the documented "report to registry" did nothing.
 *
 * The flag names are the printed-flag gate's job (__tests__/ui/
 * printed-flag-citations.test.ts); this suite holds the argument rules over
 * the same scope, README.md and docs/.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import * as path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');

function markdownFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) out.push(...markdownFiles(p));
    else if (name.endsWith('.md')) out.push(p);
  }
  return out;
}

const FILES = [path.join(REPO_ROOT, 'README.md'), ...markdownFiles(path.join(REPO_ROOT, 'docs'))];

interface Invocation {
  file: string;
  verb: string;
  /** Whitespace-split tokens after the verb, up to the next invocation or shell operator. */
  args: string[];
}

/** Every `hackmyagent <verb> ...` in fenced blocks and inline code, continuation lines joined. */
function invocations(src: string, file: string): Invocation[] {
  const regions: string[] = [];
  for (const m of src.matchAll(/(?:```|~~~)[^\n]*\n([\s\S]*?)(?:```|~~~)/g)) regions.push(m[1]);
  for (const m of src.matchAll(/`([^`\n]+)`/g)) regions.push(m[1]);
  const found: Invocation[] = [];
  for (const region of regions) {
    for (const rawLine of region.replace(/\\[ \t]*\n/g, ' ').split('\n')) {
      const line = rawLine.replace(/^\s*\$\s*/, '').replace(/\s#.*$/, '');
      for (const segment of line.split(/&&|\|\||[|;]/)) {
        const m = segment.match(/(?:^|\s)(?:(?:npx|pnpm dlx|bunx)\s+)?(?:hackmyagent|hma)(?:@[\w.-]+)?\s+([a-z][a-z0-9-]*)(.*)$/);
        if (m) found.push({ file: path.relative(REPO_ROOT, file), verb: m[1], args: m[2].trim().split(/\s+/).filter(Boolean) });
      }
    }
  }
  return found;
}

const ALL = FILES.flatMap((f) => invocations(readFileSync(f, 'utf8'), f));
const CLI_SRC = readFileSync(path.join(REPO_ROOT, 'src', 'cli.ts'), 'utf8');

function describeInvocation(i: Invocation): string {
  return `${i.file}: hackmyagent ${i.verb} ${i.args.join(' ')}`;
}

describe('documented command arguments (#762)', () => {
  it('reads real invocations (non-vacuity)', () => {
    expect(ALL.filter((i) => i.verb === 'attack').length).toBeGreaterThan(3);
    expect(ALL.filter((i) => i.verb === 'secure').length).toBeGreaterThan(10);
  });

  it('every documented attack --intensity value is one the CLI accepts', () => {
    const decl = CLI_SRC.match(/\.option\('-i, --intensity <level>', 'Attack intensity: ([a-z, ]+)'/);
    expect(decl, 'attack --intensity declaration not found in src/cli.ts').not.toBeNull();
    const allowed = decl![1].split(/,\s*/);
    expect(allowed.length).toBeGreaterThanOrEqual(3);
    const bad: string[] = [];
    for (const inv of ALL.filter((i) => i.verb === 'attack')) {
      inv.args.forEach((a, k) => {
        if ((a === '--intensity' || a === '-i') && !allowed.includes(inv.args[k + 1])) bad.push(describeInvocation(inv));
      });
    }
    expect(bad, `intensity must be one of ${allowed.join(', ')}`).toEqual([]);
  });

  it('no documented secure invocation passes a package name where a directory goes', () => {
    const bad = ALL.filter((i) => i.verb === 'secure')
      .filter((i) => i.args[0] !== undefined && (/^@[\w.-]+\//.test(i.args[0]) || /^<package/.test(i.args[0])))
      .map(describeInvocation);
    expect(bad, 'secure takes a directory; use `check <package>` for packages').toEqual([]);
  });

  it('no documented attack --local run claims to report to the Registry', () => {
    const bad = ALL.filter((i) => i.verb === 'attack' && i.args.includes('--local'))
      .filter((i) => i.args.includes('--version-id') || i.args.includes('--registry-report'))
      .map(describeInvocation);
    expect(bad, '--local contacts no agent and is never reported').toEqual([]);
  });

  it('docs name the Registry API host the CLI defaults to, not one that does not resolve', () => {
    expect(CLI_SRC).toContain("process.env.REGISTRY_URL || 'https://api.oa2a.org'");
    const naming = FILES.filter((f) => readFileSync(f, 'utf8').includes('registry.opena2a.org'))
      .map((f) => path.relative(REPO_ROOT, f));
    expect(naming).toEqual([]);
    expect(readFileSync(path.join(REPO_ROOT, 'docs', 'REGISTRY_INTEGRATION.md'), 'utf8')).toContain('https://api.oa2a.org');
  });
});
