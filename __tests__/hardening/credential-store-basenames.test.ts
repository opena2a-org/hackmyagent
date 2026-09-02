import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner, isCredentialFilePath } from '../../src/hardening/scanner';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

/**
 * HMA-30 — credential-store files (bare `credentials`, `.aws/credentials`,
 * `.kube/config`, `.env.production`) are examined by CRED-001 in directory and
 * single-file scans.
 *
 * The gap (measured at e340dcd): the CRED-001 read loop was the fixed root
 * probe list plus the walk's config-shaped files, so a bare `credentials`
 * holding a live AWS pair scored 93/100 with ZERO credential findings while the
 * identical pair in `config.json` produced CRED-001 at exit 1.
 *
 * CSR ruling 2026-09-01 (item 1): the examined population is exactly
 * `isConfigShapedFile` OR `isCredentialFilePath(absPath)` — the two predicates
 * the scanner already owns — plus ONE new bare name (`credentials`) appended to
 * SHELL_EXFIL_BARE_CRED_NAMES. No third list. SSH `id_*` files route through
 * the key-file path (CRED-002), never the CRED-001 regexes. The single-file
 * copy preserves the parent basename so the path-suffix predicates can fire.
 *
 * The AWS pair below is the inert documentation example — synthesised by join
 * so no committed line carries an AKIA-shaped literal.
 */

const AWS_PAIR =
  'aws_access_key_id = ' + ['AKIA', 'IOSFODNN7EXAMPLE'].join('') + '\n' +
  'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n';

// Header and footer are assembled from parts so no committed line carries a
// private-key-block-shaped string; the scanner sees the joined form at runtime.
const PEM_BEGIN = ['-----BEGIN RSA', 'PRIVATE KEY-----'].join(' ');
const PEM_END = ['-----END RSA', 'PRIVATE KEY-----'].join(' ');
const REPO_ROOT = path.join(__dirname, '..', '..');
const SCANNER_SRC = path.join(REPO_ROOT, 'src', 'hardening', 'scanner.ts');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const canSpawn = () => existsSync(CLI);

beforeAll(assertDistFreshIfPresent);

type Finding = { checkId: string; severity: string; passed: boolean; file?: string };

async function scanTree(contents: Record<string, string>): Promise<{ findings: Finding[] }> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma30-credstore-'));
  try {
    for (const [rel, body] of Object.entries(contents)) {
      const full = path.join(dir, rel);
      await mkdir(path.dirname(full), { recursive: true });
      await writeFile(full, body);
    }
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    return { findings: result.findings as Finding[] };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const cred001 = (findings: Finding[]) =>
  findings.filter((f) => f.checkId === 'CRED-001' && !f.passed);

describe('HMA-30 — credential-store basenames reach CRED-001', () => {
  describe('directory mode', () => {
    it('HMA-30.AC1 a scan root holding credentials, .aws/credentials, .kube/config and .env.production yields a critical CRED-001 for each of the four', async () => {
      const { findings } = await scanTree({
        credentials: AWS_PAIR,
        [path.join('.aws', 'credentials')]: AWS_PAIR,
        [path.join('.kube', 'config')]: AWS_PAIR,
        '.env.production': AWS_PAIR,
      });
      const hits = cred001(findings);
      for (const file of [
        'credentials',
        path.join('.aws', 'credentials'),
        path.join('.kube', 'config'),
        '.env.production',
      ]) {
        const hit = hits.find((f) => f.file === file);
        expect(hit, `CRED-001 for ${file}`).toBeDefined();
        expect(hit!.severity).toBe('critical');
      }
    });

    it('HMA-30.AC2 .npmrc yields CRED-001 wherever it sits when it holds the pair', async () => {
      const { findings } = await scanTree({
        '.npmrc': AWS_PAIR,
        [path.join('packages', 'app', '.npmrc')]: AWS_PAIR,
      });
      const files = cred001(findings).map((f) => f.file);
      expect(files).toContain('.npmrc');
      expect(files).toContain(path.join('packages', 'app', '.npmrc'));
    });

    it('HMA-30.AC2 .ssh/id_rsa holding a private-key block yields CRED-002 and not CRED-001', async () => {
      // The AKIA pair is planted INSIDE the key file so the "not CRED-001" half
      // is non-vacuous: routed through the CRED-001 regexes it WOULD fire.
      const { findings } = await scanTree({
        [path.join('.ssh', 'id_rsa')]:
          PEM_BEGIN + '\n' + AWS_PAIR + PEM_END + '\n',
      });
      const keyFinding = findings.find((f) => f.checkId === 'CRED-002' && !f.passed);
      expect(keyFinding, 'CRED-002 for .ssh/id_rsa').toBeDefined();
      expect(keyFinding!.file).toBe(path.join('.ssh', 'id_rsa'));
      expect(cred001(findings)).toHaveLength(0);
    });

    it("HMA-30.AC2 the population grows by exactly one bare name: a single 'credentials' literal line in scanner.ts, inside SHELL_EXFIL_BARE_CRED_NAMES", () => {
      const src = readFileSync(SCANNER_SRC, 'utf8');
      const literalLines = src.match(/^\s*'credentials',?$/gm) ?? [];
      expect(literalLines).toHaveLength(1);
      const setStart = src.indexOf('SHELL_EXFIL_BARE_CRED_NAMES = new Set([');
      expect(setStart).toBeGreaterThan(-1);
      const setBlock = src.slice(setStart, src.indexOf(']', setStart));
      expect(setBlock).toContain("'credentials'");
    });
  });

  describe('single-file mode (spawns the built CLI; skipped when dist/ is absent)', () => {
    function secureJson(target: string): Finding[] {
      const r = spawnSync('node', [CLI, 'secure', target, '--json', '--ci'], {
        encoding: 'utf8',
        timeout: 120_000,
      });
      const data = JSON.parse((r.stdout || '').trim());
      return (data.findings || []) as Finding[];
    }

    it.each([
      path.join('.aws', 'credentials'),
      path.join('.kube', 'config'),
      'credentials',
      '.env.production',
    ])('HMA-30.AC3 secure <dir>/%s yields the same critical CRED-001 as directory mode', (rel) => {
      if (!canSpawn()) return;
      const dir = mkdtempSync(path.join(tmpdir(), 'hma30-sfm-'));
      const target = path.join(dir, rel);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, AWS_PAIR);
      const hit = secureJson(target).find((f) => f.checkId === 'CRED-001' && !f.passed);
      expect(hit, `CRED-001 for lone ${rel}`).toBeDefined();
      expect(hit!.severity).toBe('critical');
      expect(path.basename(hit!.file ?? '')).toBe(path.basename(rel));
    });

    it('HMA-30.AC3 the rendered citation resolves to the original path, never <dir>/<dir-basename>/<file>', () => {
      if (!canSpawn()) return;
      const dir = mkdtempSync(path.join(tmpdir(), 'hma30-cite-'));
      const target = path.join(dir, '.aws', 'credentials');
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, AWS_PAIR);
      const r = spawnSync('node', [CLI, 'secure', target, '--ci'], {
        encoding: 'utf8',
        timeout: 120_000,
      });
      const out = (r.stdout || '') + (r.stderr || '');
      // The Verify line must name the user's path; `Scanning <target>` on line 1
      // would satisfy a bare toContain(target), so anchor on the citation.
      expect(out).toContain("Verify: sed -n '1p' " + target);
      expect(out).not.toContain(path.join(dir, '.aws', '.aws')); // the doubled-parent defect
    });

    it('HMA-30.AC3 a traversal-shaped lone target is resolved before the parent name is read, so the copy stays inside the temp dir', () => {
      // originalTarget is path.resolve'd (cli.ts) before dirname/basename are
      // taken, so `..` can never become the parent component of the copy path.
      if (!canSpawn()) return;
      const dir = mkdtempSync(path.join(tmpdir(), 'hma30-trav-'));
      const real = path.join(dir, '.aws', 'credentials');
      mkdirSync(path.dirname(real), { recursive: true });
      writeFileSync(real, AWS_PAIR);
      const shaped = path.join(dir, '.aws', '..', '.aws', 'credentials');
      const r = spawnSync('node', [CLI, 'secure', shaped, '--ci'], { encoding: 'utf8', timeout: 120_000 });
      const out = (r.stdout || '') + (r.stderr || '');
      expect(out).toContain("Verify: sed -n '1p' " + real); // the resolved path, not the shaped one
      expect(out).not.toContain(tmpdir() + path.sep + '..'); // join() would normalise this away
      expect(out).not.toContain(path.join(dir, '.aws', '.aws'));
    });

    it('HMA-30.AC6 a lone CLAUDE.md keeps CLAUDE-001 and a lone world-readable .env keeps PERM-001 and GIT-003', () => {
      // Nesting EVERY copy under its parent moved basename-matched files out of
      // the scan root, where the root-only probes stopped seeing them (review r3,
      // finding 1: lost at cc2f7b88, reported at 73383b1b).
      if (!canSpawn()) return;
      const dir = mkdtempSync(path.join(tmpdir(), 'hma30-root-'));
      const claude = path.join(dir, 'CLAUDE.md');
      writeFileSync(claude, '# agent instructions\n' + AWS_PAIR);
      const dotenv = path.join(dir, '.env');
      writeFileSync(dotenv, AWS_PAIR, { mode: 0o644 });
      const failed = (t: string) => new Set(secureJson(t).filter((f) => !f.passed).map((f) => f.checkId));
      expect(failed(claude).has('CLAUDE-001'), 'CLAUDE-001 for a lone CLAUDE.md').toBe(true);
      const envIds = failed(dotenv);
      expect(envIds.has('PERM-001'), 'PERM-001 for a lone world-readable .env').toBe(true);
      expect(envIds.has('GIT-003'), 'GIT-003 for a lone .env').toBe(true);
    });

    it('HMA-30.AC3 a symlink named credentials that leaves the parent is still withheld, not copied', () => {
      if (!canSpawn()) return;
      const base = mkdtempSync(path.join(tmpdir(), 'hma30-link-'));
      const outside = path.join(base, 'outside');
      const tree = path.join(base, 'tree');
      mkdirSync(outside);
      mkdirSync(tree);
      writeFileSync(path.join(outside, 'credentials'), AWS_PAIR);
      symlinkSync(path.join(outside, 'credentials'), path.join(tree, 'credentials'));
      const r = spawnSync('node', [CLI, 'secure', path.join(tree, 'credentials'), '--ci'], {
        encoding: 'utf8',
        timeout: 120_000,
      });
      const out = (r.stdout || '') + (r.stderr || '');
      expect(out).toMatch(/link inside the scanned tree resolves outside it and was not read/);
      expect(out).not.toMatch(/Exposed Credential/);
    });
  });

  describe('no new false-positive class', () => {
    it('HMA-30.AC5 .env.example holding the pair yields no CRED-001', async () => {
      expect(isCredentialFilePath('.env.example')).toBe(false);
      const { findings } = await scanTree({ '.env.example': AWS_PAIR });
      expect(cred001(findings)).toHaveLength(0);
    });

    it('HMA-30.AC5 a bare credentials file holding only an env-var reference yields no CRED-001', async () => {
      const { findings } = await scanTree({
        credentials: 'AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}\n',
      });
      expect(cred001(findings)).toHaveLength(0);
    });

    it('HMA-30.AC5 a root-level bare config (not .kube/config, not in a config directory) holding the pair yields no CRED-001', async () => {
      const { findings } = await scanTree({ config: AWS_PAIR });
      expect(cred001(findings)).toHaveLength(0);
    });

    it('HMA-30.AC5 no third basename list: SHELL_EXFIL_BARE_CRED_NAMES is exactly the base three plus credentials', () => {
      const src = readFileSync(SCANNER_SRC, 'utf8');
      const setStart = src.indexOf('SHELL_EXFIL_BARE_CRED_NAMES = new Set([');
      const setBlock = src.slice(setStart, src.indexOf(']', setStart));
      const members = [...setBlock.matchAll(/'([^']+)'/g)].map((m) => m[1]).sort();
      expect(members).toEqual(['.git-credentials', '.netrc', '.npmrc', 'credentials'].sort());
    });
  });
});
