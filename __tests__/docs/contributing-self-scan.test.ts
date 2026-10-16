/**
 * #1003: `secure --ci .` on this repository reports MEDIUM SANDBOX-001
 * Container Isolation on `Dockerfile`, a path that does not exist at the root
 * (the advisory names the file its fix would create; the scanner shape is
 * pinned in __tests__/hardening/absent-subject-not-applicable.test.ts).
 *
 * `.hmaignore` cannot carry it: a check-ID waiver is refused, and a narrowed
 * `<file>:<CHECK-ID>` rule must name a file that exists
 * (__tests__/hmaignore-scope-only.test.ts). So the disposition lives in the
 * "Scanning this repository" section of CONTRIBUTING.md, and this test holds
 * that section to the tree it describes: no container file at the root, one
 * Dockerfile in the repository and outside the npm package, and the `files`
 * list the section quotes.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { gitFreeEnv } from '../helpers/throwaway-repo';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CONTRIBUTING = path.join(REPO_ROOT, 'CONTRIBUTING.md');
const SELF = '__tests__/docs/contributing-self-scan.test.ts';
// #1123: the three tree checks below read the tree, not the section, so
// rewriting the section alone leaves them failing. The message names both.
const UPDATE = `update the "Scanning this repository" section of CONTRIBUTING.md and the expectation in ${SELF} that this message comes from`;

// The subjects SANDBOX-001 reads at the scanned root (checkSandboxing).
const ROOT_CONTAINER_FILES = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'];
const VHS_DOCKERFILE = 'docs/vhs/docker/Dockerfile';

function section(markdown: string, heading: string): string {
  const start = markdown.indexOf(`\n## ${heading}\n`);
  if (start === -1) return '';
  const next = markdown.indexOf('\n## ', start + 1);
  return markdown.slice(start, next === -1 ? undefined : next);
}

describe('CONTRIBUTING.md records why the self-scan reports SANDBOX-001', () => {
  const text = section(readFileSync(CONTRIBUTING, 'utf8'), 'Scanning this repository');

  it('has the section, naming the check, the command and each root file the check reads', () => {
    expect(text, 'CONTRIBUTING.md has no "## Scanning this repository" section').not.toBe('');
    expect(text).toContain(' secure --ci .\n');
    expect(text).toContain('`SANDBOX-001` Container Isolation');
    for (const name of ROOT_CONTAINER_FILES) expect(text).toContain(`\`${name}\``);
    expect(text).toContain(`\`${VHS_DOCKERFILE}\``);
  });

  it('tells the reader that a container file at the root needs both the section and this test changed', () => {
    const prose = text.replace(/\s+/g, ' ');
    expect(prose).toContain(`\`${SELF}\` fails. That test checks the tree, not this section:`);
    expect(prose).toContain('updates both this section and the expectations in that test.');
    expect(prose).not.toContain('fails until this section is updated');
    expect(UPDATE).toContain('section of CONTRIBUTING.md');
    expect(UPDATE).toContain(SELF);
    expect(existsSync(path.join(REPO_ROOT, SELF))).toBe(true);
  });

  it('the root holds none of the files SANDBOX-001 reads', () => {
    const present = ROOT_CONTAINER_FILES.filter((name) => existsSync(path.join(REPO_ROOT, name)));
    expect(present, `a container file now sits at the root; ${UPDATE}`).toEqual([]);
  });

  it('the one tracked Dockerfile is the VHS recording image', () => {
    // gitFreeEnv(): under the pre-push hook git exports GIT_DIR, which would
    // point this listing at whatever repository the hook was fired from (#348).
    const tracked = execFileSync('git', ['ls-files', '-z', '--', '*Dockerfile*', '*docker-compose*'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: gitFreeEnv(),
    })
      .split('\0')
      .filter(Boolean);
    expect(tracked, `the tracked container files changed; ${UPDATE}`).toEqual([VHS_DOCKERFILE]);
  });

  it('the npm package carries the files the section lists and not the VHS image', () => {
    const files: string[] = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')).files;
    expect(files, `package.json "files" changed; ${UPDATE}`).toEqual(['dist', 'README.md', 'LICENSE']);
    for (const entry of files) expect(text).toContain(`\`${entry}\``);
    expect(files.some((entry) => VHS_DOCKERFILE === entry || VHS_DOCKERFILE.startsWith(`${entry}/`))).toBe(false);
  });
});
