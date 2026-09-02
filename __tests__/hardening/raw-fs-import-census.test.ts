/**
 * Static census of raw `fs` imports under `src/`.
 *
 * Out-of-tree link confinement is enforced once, in the tracked namespace
 * (`src/hardening/tracked-fs.ts`), which is complete for every caller of that
 * namespace by construction. What it cannot see is a reader that imports
 * `fs` directly. This test walks `src/` for every spelling of that import and
 * holds the set of files to a pinned allowlist, each entry carrying the reason
 * its raw use is contained (or is off the scan path). A new raw import fails
 * here until it is routed through `tracked-fs` or allowlisted with a
 * site-level check — the allowlist is the census, and the census is the
 * review trigger.
 *
 * Also pinned here (AC8): the guard's member lists, that `checkFilePermissions`
 * was not edited into a site-level check, and that no CLI flag follows links
 * out.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const SRC = path.resolve(__dirname, '../../src');

const RAW_FS_IMPORT = [
  /from\s+['"](?:node:)?fs(?:\/promises)?['"]/,
  /require\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)/,
  /import\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)/,
];

/**
 * The census. Keys are `src/`-relative paths; values are the containment
 * justification. "scan path" means the module is reached by `secure` or the
 * MCP scan tools; every other entry says why it is not.
 */
const ALLOWLIST: Record<string, string> = {
  // Scan path — confined or contained.
  'hardening/tracked-fs.ts': 'the namespace itself: the guard wraps the raw functions it imports',
  'hardening/coverage-ledger.ts': 'realpathSync only, the guard\'s instrument; reads no target content',
  'hardening/contain.ts': 'realpath/lstat identity checks on paths about to be acted on; the site-level confinement helper',
  'hardening/scanner.ts': 'raw fsSync: accessSync on ancestors (lexically outside the root), realpathSync.native identity, readFileSync in readArtifactForCitation confined by readStaysInsideTree',
  'nanomind-core/scanner-bridge.ts': 'two raw readFileSync sites (policy probe, citation re-read), each confined by readStaysInsideTree; discovery goes through tracked-fs',
  'cli.ts': 'single-file copy confined by readStaysInsideTree with root = the argument\'s own directory; target stat is lstat-first; the --deep text-mode simulation walk (findSkills) is lstat-first and skips links resolving outside the target; the secure --fix governance pre-hash is confined by readStaysInsideTree against the scan target (the scan-soul/harden-soul/detect governance reads are confined at their own sites — see the soul/scanner.ts and scanner/detect.ts rows); remaining raw reads are HMA\'s own files and --output writes',
  'semantic/structural/git-context.ts': 'link metadata only (lstat/readlink/realpath), deliberately resolves to classify; reads no content',
  'mcp/roots.ts': 'resolves the granted roots and the requested directory against them; the entry-path confinement',
  'soul/scanner.ts': 'governance --fix path (hardenSoul), write side, contained by #270 resolveInsideTree; read side (findGovernanceFile routing plus the scanSoul and hardenSoul reads) confined by readStaysInsideTree against the scanned tree root, resolved-first so a file target never stats through an out-of-tree link',
  'nanomind-core/security/integrity-verifier.ts': 'reads HMA\'s own dist manifest, never a target path',
  'nanomind-core/inference/tme-classifier.ts': 'HMA\'s own model cache under the home directory, never a target path',
  'nanomind-core/inference/tme-neural.ts': 'HMA\'s own model files, never a target path',
  'nanomind-core/inference/security-analyst.ts': 'HMA\'s own model files, never a target path',
  'nanomind-core/inference/nanomind-guard-client.ts': 'HMA\'s own socket/config paths, never a target path',
  'nanomind-core/daemon-lifecycle.ts': 'HMA\'s own daemon pid/socket files, never a target path',
  'semantic/llm/cache.ts': 'HMA\'s own response cache under the home directory',
  'semantic/llm/budget.ts': 'HMA\'s own budget file under the home directory',
  'telemetry/contribute.ts': 'HMA\'s own queue files under the home directory',
  'telemetry/opt-in.ts': 'HMA\'s own opt-in record under the home directory',
  'store/project-store.ts': 'HMA\'s own project store under the home directory',
  'hardening/nemoclaw-scanner.ts': 'not constructed anywhere in src/ (0 `new NemoClawScanner` sites); off the scan path',
  // Off the scan path — other commands.
  'index.ts': 'library entry; re-exports only',
  'init-mcp.ts': 'writes the MCP client config the user names',
  'aap/client.ts': 'AAP command; not reached by secure',
  'aap/trust-gate.ts': 'AAP command; not reached by secure',
  'attack-engine/training-pipeline.ts': 'training tooling; not reached by secure',
  'checker/skill-dependency-graph.ts': 'check command; not reached by secure',
  'eval/oracle.ts': 'evaluation tooling; not reached by secure',
  'oasb/harness/arp-wrapper.ts': 'ARP harness; not reached by secure',
  'plugins/credvault.ts': 'plugin; not reached by secure',
  'plugins/signcrypt.ts': 'plugin; not reached by secure',
  'plugins/skillguard.ts': 'plugin; not reached by secure',
  'registry/publish.ts': 'publish arm reads package.json of the target to name it; runs after the scan, contents not scanned',
  'narrative/wire-publish.ts': '--publish arm: reads SKILL.md / package.json of the target and POSTs the narrative; both reads confined by readStaysInsideTree',
  'scanner/detect.ts': 'detect command; not reached by secure, and its governance-named reads (scanAiConfigs stat + read of .cursorrules / CLAUDE.md / copilot-instructions, and scanSoul via the soul scanner) are confined by readStaysInsideTree against the scanned tree',
  'skills/builder.ts': 'skill builder; not reached by secure',
};

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts') && !entry.name.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

describe('raw fs import census', () => {
  const importers = walk(SRC)
    .filter((f) => {
      const text = readFileSync(f, 'utf8');
      return RAW_FS_IMPORT.some((re) => re.test(text));
    })
    .map((f) => path.relative(SRC, f))
    .sort();

  it('every raw fs importer under src/ is on the pinned allowlist with a justification', () => {
    const unlisted = importers.filter((f) => !(f in ALLOWLIST));
    expect(unlisted, 'raw fs importers not in the census (route through tracked-fs or allowlist with a site-level check)').toEqual([]);
  });

  it('the allowlist carries no stale entry', () => {
    const stale = Object.keys(ALLOWLIST).filter((f) => !importers.includes(f));
    expect(stale, 'allowlist entries that no longer import raw fs').toEqual([]);
  });

  it('every entry has a non-empty justification', () => {
    for (const [file, why] of Object.entries(ALLOWLIST)) {
      expect(why.trim().length, file).toBeGreaterThan(20);
    }
  });

  it('the four raw scan-path read sites call the site-level confinement', () => {
    const scanner = readFileSync(path.join(SRC, 'hardening/scanner.ts'), 'utf8');
    const citation = scanner.slice(scanner.indexOf('private readArtifactForCitation('));
    expect(citation.slice(0, 900)).toContain('readStaysInsideTree(');

    const bridge = readFileSync(path.join(SRC, 'nanomind-core/scanner-bridge.ts'), 'utf8');
    const policy = bridge.slice(bridge.indexOf('for (const candidate of governanceFileCandidates)'));
    expect(policy.slice(0, policy.indexOf('readFileSync(candidate'))).toContain('readStaysInsideTree(candidate');
    const reread = bridge.slice(bridge.indexOf('const readArtifact = (file: string)'));
    expect(reread.slice(0, reread.indexOf('readFileSync(filePath'))).toContain('readStaysInsideTree(filePath');

    const cli = readFileSync(path.join(SRC, 'cli.ts'), 'utf8');
    const copy = cli.slice(cli.indexOf("'hma-secure-file-'"));
    expect(copy.slice(0, copy.indexOf('copyFileSync(originalTarget'))).toContain('readStaysInsideTree(originalTarget');
  });
});

describe('the guard lives once in tracked-fs', () => {
  const tracked = readFileSync(path.join(SRC, 'hardening/tracked-fs.ts'), 'utf8');

  it('guards exactly the link-following members, parent-only for lstat/readlink, and realpath passes through', () => {
    expect(tracked).toMatch(/const LINK_FOLLOWING = \['readFile', 'stat', 'access', 'readdir', 'opendir', 'open'\] as const;/);
    expect(tracked).toMatch(/const PARENT_ONLY = \['lstat', 'readlink'\] as const;/);
    expect(tracked).not.toMatch(/confine\([^)]*'realpath'/);
  });

  it('refuses ENOENT-shaped and asks the ledger, not a predicate of its own', () => {
    expect(tracked).toContain("err.code = 'ENOENT'");
    expect(tracked).toContain('withholdOutOfTree(');
    // No lexical containment of its own: `startsWith(` with a separator is
    // the ledger's job.
    expect(tracked).not.toMatch(/startsWith\([^)]*path\.sep/);
  });

  it('checkFilePermissions is not edited into a site-level check', () => {
    const scanner = readFileSync(path.join(SRC, 'hardening/scanner.ts'), 'utf8');
    const start = scanner.indexOf('private async checkFilePermissions(');
    expect(start).toBeGreaterThan(0);
    const next = scanner.indexOf('\n  private ', start + 10);
    const body = scanner.slice(start, next);
    expect(body).not.toMatch(/realpath|withheld|readStaysInsideTree|confine/i);
  });

  it('no CLI flag follows links out', () => {
    const cli = readFileSync(path.join(SRC, 'cli.ts'), 'utf8');
    expect(cli).not.toMatch(/--follow-links|--no-confine|--unconfined|followLinksOut|allowOutOfTree/);
    const scanner = readFileSync(path.join(SRC, 'hardening/scanner.ts'), 'utf8');
    expect(scanner).not.toMatch(/followLinksOut|allowOutOfTree|unconfined\?:/);
  });
});
