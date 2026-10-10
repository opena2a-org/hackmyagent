/**
 * `withoutUrlUserinfo`: the form of a URL that `check <URL>` prints, writes to
 * `--json` and publishes, with the user name and password (or token) removed.
 * `scanNameWithoutUserinfo`: the same for a scan name an earlier version made
 * from such a URL and left in the pending-scan queue.
 *
 * Every value that carries userinfo is assembled at runtime from a userinfo
 * part and the rest, so no line of this file spells a credential-bearing URL.
 */
import { describe, it, expect } from 'vitest';
import { scanNameWithoutUserinfo, withoutUrlUserinfo } from '../../src/check/url-userinfo';

const SECRET = ['FAKE', 'secret', '123'].join('');

/** `<scheme>://<userinfo>@<rest>`, built at runtime. */
function withUserinfo(scheme: string, userinfo: string, rest: string): string {
  return `${scheme}://${userinfo}@${rest}`;
}

describe('withoutUrlUserinfo', () => {
  it('removes a user name and password', () => {
    const typed = withUserinfo('https', `alice:${SECRET}`, 'gitlab.com/example-org/example-repo.git');
    expect(withoutUrlUserinfo(typed)).toBe('https://gitlab.com/example-org/example-repo.git');
  });

  it('removes a user name alone and a token alone', () => {
    expect(withoutUrlUserinfo(withUserinfo('https', 'alice', 'codeberg.org/org/repo.git')))
      .toBe('https://codeberg.org/org/repo.git');
    expect(withoutUrlUserinfo(withUserinfo('https', SECRET, 'gitlab.com/org/repo.git')))
      .toBe('https://gitlab.com/org/repo.git');
    expect(withoutUrlUserinfo(withUserinfo('http', `oauth2:${SECRET}`, 'git.example.com:8080/org/repo.git')))
      .toBe('http://git.example.com:8080/org/repo.git');
  });

  it('removes every `@` of a password that carries one, encoded or not', () => {
    expect(withoutUrlUserinfo(withUserinfo('https', `alice:${SECRET}%40x`, 'gitlab.com/org/repo.git')))
      .toBe('https://gitlab.com/org/repo.git');
    expect(withoutUrlUserinfo(withUserinfo('https', `alice:${SECRET}@x`, 'gitlab.com/org/repo.git')))
      .toBe('https://gitlab.com/org/repo.git');
  });

  it('removes userinfo whatever the case of the scheme, and from a URL with no path', () => {
    expect(withoutUrlUserinfo(withUserinfo('HTTPS', `alice:${SECRET}`, 'gitlab.com/org/repo.git')))
      .toBe('HTTPS://gitlab.com/org/repo.git');
    expect(withoutUrlUserinfo(withUserinfo('https', `alice:${SECRET}`, 'example.com')))
      .toBe('https://example.com');
  });

  it('returns a URL without userinfo unchanged, character for character', () => {
    for (const url of [
      'https://gitlab.com/example-org/example-repo.git',
      'https://GitLab.com:443/Org/Repo.git',
      'https://example.com/releases/agent-1.0.0.tar.gz?download=1#top',
      'http://127.0.0.1:9/pkg.tar.gz',
    ]) {
      expect(withoutUrlUserinfo(url)).toBe(url);
    }
  });

  it('keeps an `@` that comes after the first `/` of the path', () => {
    const url = 'https://gitlab.com/org/repo@v1.git';
    expect(withoutUrlUserinfo(url)).toBe(url);
    expect(withoutUrlUserinfo(withUserinfo('https', `alice:${SECRET}`, 'gitlab.com/org/repo@v1.git')))
      .toBe('https://gitlab.com/org/repo@v1.git');
  });

  it('returns a string that is not `scheme://...` as it is', () => {
    for (const value of ['unknown', 'org/repo', 'git@github.com:org/repo.git', '']) {
      expect(withoutUrlUserinfo(value)).toBe(value);
    }
  });
});

describe('scanNameWithoutUserinfo', () => {
  it('removes the userinfo from a scan name made from a git URL', () => {
    expect(scanNameWithoutUserinfo(`alice:${SECRET}@gitlab.com/org/repo`)).toBe('gitlab.com/org/repo');
    expect(scanNameWithoutUserinfo(`alice:${SECRET}@x@gitlab.com/org/repo`)).toBe('gitlab.com/org/repo');
    expect(scanNameWithoutUserinfo(`${SECRET}@git.example.com:8080/org/repo`)).toBe('git.example.com:8080/org/repo');
  });

  it('returns the other names a scan is queued under unchanged', () => {
    for (const name of [
      'org/repo',
      '@scope/pkg',
      'left-pad',
      'pkg@1.0.0',
      '@scope/pkg@1.0.0',
      'gitlab.com/org/repo',
      'gitlab.com/org/repo@v1',
      'agent-1.0.0.tar.gz',
      '',
    ]) {
      expect(scanNameWithoutUserinfo(name)).toBe(name);
    }
  });
});
