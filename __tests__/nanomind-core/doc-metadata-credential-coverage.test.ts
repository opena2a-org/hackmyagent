/**
 * #1027 — the semantic layer skipped every file whose basename BEGAN with
 * readme, changelog, license, contributing, history or authors, plus
 * package.json, package-lock.json, tsconfig.json and .npmrc, before any
 * analyzer ran. A planted token in `CHANGELOG.md`, `src/history.ts` or the
 * `scripts` of a `package.json` was reported by nothing.
 *
 * The rule that replaced the skip:
 *   - no basename prefix test; source and config files with those names get
 *     their ordinary route;
 *   - `package-lock.json` alone stays out of the analyzers;
 *   - `package.json` and `tsconfig.json` take the non-agent route;
 *   - the six document names (exact, optionally `.md` and similar) take the
 *     non-agent route, and keep their `AST-CRED-*` findings only when the file
 *     carries a vendor-prefixed credential that is not a placeholder.
 *
 * Real compiler, real analyzers, real temp trees. Every credential-shaped
 * value is assembled at run time from a seeded hash, never written as a
 * literal, and every file in a tree has bytes of its own: the compiler serves
 * a cached AST, path included, to byte-identical files of the same type, so
 * two files with the same bytes would share one set of findings.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { tempDir } from '../helpers/temp-dir';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import type { NanoMindScanResult } from '../../src/nanomind-core/scanner-bridge';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import {
  analyzerRouteFor,
  isDocumentBasename,
  lowerBasename,
} from '../../src/nanomind-core/analyzers/family-coverage';
import {
  hasNonPlaceholderVendorCredential,
  isPlaceholderCredentialBody,
} from '../../src/nanomind-core/document-vendor-tier';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const DIGITS = '0123456789';

/** `length` characters of `alphabet`, derived from `seed`: stable across runs. */
function seeded(seed: string, length: number, alphabet = ALNUM): string {
  let out = '';
  for (let counter = 0; out.length < length; counter++) {
    for (const byte of createHash('sha256').update(`${seed}:${counter}`).digest()) {
      if (out.length === length) break;
      out += alphabet[byte % alphabet.length];
    }
  }
  return out;
}

/** A token body that is not a placeholder, so a fixture cannot pass by accident. */
function realBody(seed: string, length: number, alphabet = ALNUM): string {
  const body = seeded(seed, length, alphabet);
  if (isPlaceholderCredentialBody(body)) throw new Error(`fixture body for ${seed} reads as a placeholder`);
  return body;
}

/** A GitHub-shaped token: the prefix is joined at run time. */
const githubToken = (seed: string, body = realBody(seed, 36)) => ['gh', 'p_'].join('') + body;

/** A Slack-bot-shaped token: the prefix is joined at run time. */
const slackBotToken = (seed: string) =>
  ['xo', 'xb-'].join('') +
  [realBody(`${seed}-a`, 12, DIGITS), realBody(`${seed}-b`, 13, DIGITS), realBody(`${seed}-c`, 24)].join('-');

/** A 40-character hex value with no vendor prefix. */
const hex40 = (seed: string) => createHash('sha1').update(seed).digest('hex');

/** The 1-based line of the first line containing `needle`. */
function lineOf(content: string, needle: string): number {
  const index = content.split('\n').findIndex((line) => line.includes(needle));
  if (index === -1) throw new Error('needle not in content');
  return index + 1;
}

async function scanTree(files: Record<string, string>): Promise<NanoMindScanResult> {
  const dir = tempDir('hma-docmeta-');
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content, 'utf-8');
  }
  return runNanoMindScan(dir, []);
}

interface CredRow {
  checkId: string;
  file: string | undefined;
  line: number | undefined;
}

function credRows(result: NanoMindScanResult, file?: string): CredRow[] {
  return result.mergedFindings
    .filter((f) => !f.passed && f.checkId.startsWith('AST-CRED-'))
    .map((f) => ({ checkId: f.checkId, file: f.file, line: f.line }))
    .filter((row) => file === undefined || row.file === file);
}

function routeOf(result: NanoMindScanResult, path: string) {
  for (const group of result.semanticFamilyCoverage.partial) {
    if (group.examplePaths.includes(path)) {
      return { route: group.route, families: group.familiesExamined, artifactType: group.artifactType };
    }
  }
  return undefined;
}

/** A document with a token on its own line, and a heading that keeps its bytes unique. */
function documentWithToken(title: string, token: string): string {
  return `# ${title}\n\nSet up the release job.\n\nGITHUB_TOKEN=${token}\n\nThen run the publish step.\n`;
}

describe('#1027: documentation and metadata files reach the credential family', () => {
  it('a: a vendor token in each of the seven document names is reported at its line', async () => {
    const names = [
      'README.md',
      'docs/README.md',
      'CHANGELOG.md',
      'CONTRIBUTING.md',
      'HISTORY.md',
      'AUTHORS.md',
      'LICENSE.md',
    ];
    const files: Record<string, string> = {};
    const tokens: Record<string, string> = {};
    for (const name of names) {
      tokens[name] = githubToken(`a:${name}`);
      files[name] = documentWithToken(name, tokens[name]);
    }
    const result = await scanTree(files);

    for (const name of names) {
      const rows = credRows(result, name);
      expect(rows.map((r) => r.checkId), `${name} must report its token`).toContain('AST-CRED-003');
      const at = rows.find((r) => r.checkId === 'AST-CRED-003');
      expect(at?.line, `${name}: the finding must sit on the token's line`).toBe(lineOf(files[name], tokens[name]));
    }
  });

  it('b: source and config files whose names begin with the six words report what their control names report', async () => {
    const pairs: Array<[string, string]> = [
      ['src/history.ts', 'src/store.ts'],
      ['src/historyStore.ts', 'src/cacheStore.ts'],
      ['src/license-check.js', 'src/input-check.js'],
      ['src/readme-generator.js', 'src/page-generator.js'],
      ['src/changelog.config.js', 'src/build.config.js'],
      ['src/authors.ts', 'src/members.ts'],
      ['app/authors.py', 'app/members.py'],
      ['app/history.py', 'app/settings.py'],
      ['data/history.json', 'data/session.json'],
      ['data/licenses.json', 'data/accounts.json'],
      ['ci/contributing.yml', 'ci/deploy.yml'],
    ];
    const template = (path: string, token: string): string => {
      if (path.endsWith('.py')) return `RELEASE_TOKEN = "${token}"\n`;
      if (path.endsWith('.json')) return `{\n  "releaseToken": "${token}"\n}\n`;
      if (path.endsWith('.yml')) return `release:\n  token: ${token}\n`;
      return `export const release = {\n  token: "${token}",\n};\n`;
    };
    const files: Record<string, string> = {};
    for (const [named, control] of pairs) {
      files[named] = template(named, githubToken(`b:${named}`));
      files[control] = template(control, githubToken(`b:${control}`));
    }
    const result = await scanTree(files);

    // The credential analyzer's own documentation test matches `readme`
    // anywhere in a path and skips AST-CRED-001 there, so this one file reports
    // a subset of its control. That path test lives in the analyzer and is not
    // part of this rule; the skip it replaced hid the file from every check.
    const analyzerDocPath = new Set(['src/readme-generator.js']);
    const idsOf = (path: string) => [...new Set(credRows(result, path).map((r) => r.checkId))].sort();
    for (const [named, control] of pairs) {
      expect(idsOf(control).length, `control ${control} must report its token`).toBeGreaterThan(0);
      expect(idsOf(named), `${named} must report its token`).toContain('AST-CRED-003');
      if (analyzerDocPath.has(named)) {
        for (const id of idsOf(named)) expect(idsOf(control), `${named} vs ${control}`).toContain(id);
      } else {
        expect(idsOf(named), `${named} must report what ${control} reports`).toEqual(idsOf(control));
      }
    }
  });

  it('c: a token in the scripts of a package.json, scanned alone, is reported at its line', async () => {
    const token = githubToken('c:package.json');
    const manifest =
      '{\n  "name": "demo",\n  "version": "1.0.0",\n  "scripts": {\n' +
      `    "release": "GITHUB_TOKEN=${token} node release.js"\n  }\n}\n`;
    const result = await scanTree({ 'package.json': manifest });

    const rows = credRows(result, 'package.json').filter((r) => r.checkId === 'AST-CRED-003');
    expect(rows.map((r) => r.line)).toContain(lineOf(manifest, token));
    expect(routeOf(result, 'package.json')?.route).toBe('non_agent');
  });

  it('c: a token in a tsconfig.json is reported', async () => {
    const token = githubToken('c:tsconfig.json');
    const tsconfig =
      '{\n  "compilerOptions": {\n    "strict": true\n  },\n  "release": {\n' +
      `    "token": "${token}"\n  }\n}\n`;
    const result = await scanTree({ 'tsconfig.json': tsconfig });

    expect(credRows(result, 'tsconfig.json').map((r) => r.checkId)).toContain('AST-CRED-003');
  });

  it('d: package-lock.json stays out of the analyzers and its integrity values report nothing', async () => {
    const integrity = (seed: string) => `sha512-${createHash('sha512').update(seed).digest('base64')}`;
    const lock =
      '{\n  "name": "demo",\n  "lockfileVersion": 3,\n  "packages": {\n' +
      ['left-pad', 'right-pad', 'center-pad']
        .map(
          (name) =>
            `    "node_modules/${name}": {\n      "version": "1.3.0",\n` +
            `      "integrity": "${integrity(name)}"\n    }`,
        )
        .join(',\n') +
      '\n  }\n}\n';
    const result = await scanTree({ 'package-lock.json': lock });

    expect(credRows(result)).toEqual([]);
    expect(routeOf(result, 'package-lock.json')).toMatchObject({ route: 'not_routed', families: [] });
  });

  describe('e: placeholders in the six document names', () => {
    const openaiPrefix = ['s', 'k-'].join('');
    const stripeLivePrefix = ['sk', '_live_'].join('');
    const awsDocsExample = ['AK', 'IA'].join('') + 'IOSFODNN7' + 'EXAMPLE';
    const placeholders = [
      githubToken('e:x', 'x'.repeat(36)),
      githubToken('e:0', '0'.repeat(36)),
      githubToken('e:run', 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'),
      githubToken('e:fake', `FAKE${seeded('e:fake', 32)}`),
      githubToken('e:example', `EXAMPLE${seeded('e:example', 29)}`),
      githubToken('e:placeholder', `PLACEHOLDER${seeded('e:placeholder', 25)}`),
      `${openaiPrefix}YOUR_API_KEY_GOES_HERE_${seeded('e:your', 8)}`,
      `${stripeLivePrefix}DUMMY${seeded('e:dummy', 24)}`,
      awsDocsExample,
    ];
    const placeholderDoc = (title: string) =>
      `# ${title}\n\nConfigure the client:\n\n` +
      placeholders.map((value, i) => `- KEY_${i}=${value}`).join('\n') +
      '\n';

    it('report no AST-CRED finding in README.md and CHANGELOG.md', async () => {
      const result = await scanTree({
        'README.md': placeholderDoc('Readme'),
        'CHANGELOG.md': placeholderDoc('Changelog'),
      });
      expect(credRows(result, 'README.md')).toEqual([]);
      expect(credRows(result, 'CHANGELOG.md')).toEqual([]);
    });

    it('while a random Slack bot token in README.md is reported', async () => {
      const token = slackBotToken('e:slack');
      const readme = `# Readme\n\nThe bot posts with:\n\nSLACK_BOT_TOKEN=${token}\n`;
      const result = await scanTree({ 'README.md': readme });
      const rows = credRows(result, 'README.md').filter((r) => r.checkId === 'AST-CRED-003');
      expect(rows.map((r) => r.line)).toContain(lineOf(readme, token));
    });

    it('and a placeholder earlier in the file does not hide a real token after it', async () => {
      const token = githubToken('e:after');
      const readme = placeholderDoc('Readme') + `\nGITHUB_TOKEN=${token}\n`;
      const result = await scanTree({ 'README.md': readme });
      const rows = credRows(result, 'README.md').filter((r) => r.checkId === 'AST-CRED-003');
      expect(rows.map((r) => r.line)).toContain(lineOf(readme, token));
    });
  });

  it('f: a prefix-free 40-hex value is not reported in README.md or CHANGELOG.md, and is in notes.md', async () => {
    // The disclosed residual of the vendor tier, pinned in both directions:
    // the two documents stay silent, and notes.md, which is not one of the six
    // names, keeps the analyzer's ordinary behaviour.
    const doc = (title: string, seed: string) => `# ${title}\n\nAPI_SECRET=${hex40(seed)}\n`;
    const result = await scanTree({
      'README.md': doc('Readme', 'f:readme'),
      'CHANGELOG.md': doc('Changelog', 'f:changelog'),
      'notes.md': doc('Notes', 'f:notes'),
    });
    expect(credRows(result, 'README.md')).toEqual([]);
    expect(credRows(result, 'CHANGELOG.md')).toEqual([]);
    expect(credRows(result, 'notes.md').map((r) => r.checkId)).toContain('AST-CRED-003');
  });

  it('g: a CHANGELOG with commit links and one vendor token reports exactly one AST-CRED-003, at the token', async () => {
    const commitLine = (version: string, subject: string) => {
      const sha = hex40(`g:${version}`);
      return (
        `## ${version}\n\n` +
        `- ${subject} ([${sha.slice(0, 7)}](https://github.com/example/demo/commit/${sha}))\n`
      );
    };
    const token = githubToken('g:token');
    const changelog =
      '# Changelog\n\n' +
      commitLine('2.1.0', 'retry the upload once on a timeout') +
      '\n' +
      commitLine('2.0.1', 'read the proxy from the environment') +
      `\nThe publish job reads GITHUB_TOKEN=${token} from this file.\n\n` +
      commitLine('2.0.0', 'drop the legacy client');
    const result = await scanTree({ 'CHANGELOG.md': changelog });

    const rows = credRows(result, 'CHANGELOG.md').filter((r) => r.checkId === 'AST-CRED-003');
    expect(rows).toHaveLength(1);
    expect(rows[0].line).toBe(lineOf(changelog, token));
  });

  describe('h: routing', () => {
    it('README.md takes the non-agent route, examined by credentials and stego', async () => {
      const result = await scanTree({ 'README.md': '# Readme\n\nA plain document.\n' });
      expect(routeOf(result, 'README.md')).toMatchObject({
        route: 'non_agent',
        families: ['credentials', 'stego'],
      });
    });

    it('a package.json carrying mcpServers compiles as mcp_config and still takes the non-agent route', async () => {
      const manifest =
        '{\n  "name": "demo",\n  "mcpServers": {\n    "files": { "command": "node", "args": ["server.js"] }\n  }\n}\n';
      const result = await scanTree({ 'package.json': manifest });
      expect(routeOf(result, 'package.json')).toMatchObject({ route: 'non_agent', artifactType: 'mcp_config' });
    });

    it('src/history.ts takes the source-code route', async () => {
      const result = await scanTree({ 'src/history.ts': 'export const history: string[] = [];\n' });
      expect(routeOf(result, 'src/history.ts')?.route).toBe('source_code');
    });

    it('a package.json and an mcp.json with the same bytes each take their own route, in either order', async () => {
      // The compiler serves the first file's cached AST, path included, to the
      // second; the route must follow the path the bridge read, not that one.
      const shared =
        '{\n  "mcpServers": {\n    "files": { "command": "node", "args": ["server.js"] }\n  }\n}\n';
      for (const [first, second] of [
        ['a/package.json', 'b/mcp.json'],
        ['a/mcp.json', 'b/package.json'],
      ]) {
        const result = await scanTree({ [first]: shared, [second]: shared });
        const manifest = first.endsWith('package.json') ? first : second;
        const mcp = first.endsWith('mcp.json') ? first : second;
        const routes = new Map<string, string>();
        for (const group of result.semanticFamilyCoverage.partial) {
          for (const p of group.examplePaths) routes.set(p, group.route);
        }
        expect(routes.get(manifest), `${manifest} after ${first}`).toBe('non_agent');
        // Only the agent route invokes all seven families, so an artifact
        // missing from `partial` took it.
        expect(routes.get(mcp) ?? 'agent', `${mcp} after ${first}`).toBe('agent');
      }
    });

    it('analyzerRouteFor reads the document and metadata names from the path it is given', async () => {
      const compiler = new SemanticCompiler({ useNanoMind: false });
      const { ast } = await compiler.compile(
        '{\n  "mcpServers": {\n    "files": { "command": "node", "args": ["server.js"] }\n  }\n}\n',
        'mcp.json',
      );
      expect(ast.artifactType).toBe('mcp_config');
      expect(analyzerRouteFor(ast)).toBe('agent');
      expect(analyzerRouteFor(ast, 'mcp.json')).toBe('agent');
      expect(analyzerRouteFor(ast, 'package.json')).toBe('non_agent');
      expect(analyzerRouteFor(ast, 'sub/tsconfig.json')).toBe('non_agent');
      expect(analyzerRouteFor(ast, 'docs\\README.md')).toBe('non_agent');
    });
  });
});

describe('#1027: the document and placeholder predicates', () => {
  it('names exactly the six documents, on either separator', () => {
    for (const path of [
      'README.md',
      'readme',
      'docs/Changelog.markdown',
      'docs\\README.md',
      'LICENSE.txt',
      'contributing.rst',
      'HISTORY.adoc',
      'AUTHORS',
    ]) {
      expect(isDocumentBasename(path), path).toBe(true);
    }
    for (const path of [
      'src/history.ts',
      'changelog.config.js',
      'README-generator.md',
      'docs/readme.md.bak',
      'notes.md',
      'CHANGES.md',
      'package.json',
    ]) {
      expect(isDocumentBasename(path), path).toBe(false);
    }
    expect(lowerBasename('a\\b/C.MD')).toBe('c.md');
  });

  it('reads a fixture word, a repeated character or an ordered run as a placeholder', () => {
    expect(isPlaceholderCredentialBody('x'.repeat(36))).toBe(true);
    expect(isPlaceholderCredentialBody('0'.repeat(36))).toBe(true);
    expect(isPlaceholderCredentialBody('aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789')).toBe(true);
    expect(isPlaceholderCredentialBody(`zz${'klmnopqrstuvwxyz'}zz`)).toBe(true);
    expect(isPlaceholderCredentialBody(`${seeded('p:fake', 10)}fake${seeded('p:fake2', 10)}`)).toBe(true);
    expect(isPlaceholderCredentialBody(seeded('p:real', 36))).toBe(false);
    // Fifteen characters of the ordered run are not enough.
    expect(isPlaceholderCredentialBody(`Q${'abcdefghijklmno'}Q${seeded('p:short', 10)}`)).toBe(false);
  });

  it('removes the vendor prefix first, so a Stripe test key is not a placeholder by its prefix', () => {
    const stripeTest = ['sk', '_test_'].join('') + realBody('p:stripe', 24);
    expect(hasNonPlaceholderVendorCredential(`key: ${stripeTest}\n`)).toBe(true);
  });

  it('finds the real token after a placeholder, and nothing in a file of placeholders', () => {
    const placeholder = githubToken('p:x', 'x'.repeat(36));
    expect(hasNonPlaceholderVendorCredential(`a=${placeholder}\n`)).toBe(false);
    expect(hasNonPlaceholderVendorCredential(`a=${placeholder}\nb=${githubToken('p:after')}\n`)).toBe(true);
    expect(hasNonPlaceholderVendorCredential(`API_SECRET=${hex40('p:hex')}\n`)).toBe(false);
  });
});
