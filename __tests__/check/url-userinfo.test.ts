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
import { scanNameWithoutUserinfo, withoutUrlQueryAndFragment, withoutUrlUserinfo } from '../../src/check/url-userinfo';

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

  it('removes an empty userinfo, the `@` of `https://@<host>/...`, for git and for fetch', () => {
    for (const reader of ['git', 'fetch'] as const) {
      expect(withoutUrlUserinfo(withUserinfo('https', '', 'gitlab.com/org/repo.git'), reader))
        .toBe('https://gitlab.com/org/repo.git');
      expect(withoutUrlUserinfo(withUserinfo('https', ':', 'gitlab.com/org/repo.git'), reader))
        .toBe('https://gitlab.com/org/repo.git');
      expect(withoutUrlUserinfo(withUserinfo('http', '', 'localhost:8080/pkg.tgz'), reader))
        .toBe('http://localhost:8080/pkg.tgz');
    }
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

  // No userinfo, and an `@` after the host in the query or the fragment.
  const AT_AFTER_THE_AUTHORITY = [
    'http://localhost?ref=@evil.example/pkg.tgz',
    'http://localhost?file=pkg@1.0.0',
    'http://localhost#@evil.example/pkg.tgz',
    'https://gitlab.com?ref=@evil.example/org/repo.git',
    'https://gitlab.com#@evil.example/org/repo.git',
  ];

  it('ends the authority at `?` and `#` for git and for fetch, so an `@` after it is left alone', () => {
    for (const reader of ['git', 'fetch'] as const) {
      for (const url of AT_AFTER_THE_AUTHORITY) expect(withoutUrlUserinfo(url, reader)).toBe(url);
    }
  });

  it('still removes userinfo that comes before a query or a fragment holding an `@`', () => {
    for (const reader of ['git', 'fetch'] as const) {
      expect(withoutUrlUserinfo(withUserinfo('https', `alice:${SECRET}`, 'gitlab.com?ref=@evil.example/org/repo.git'), reader))
        .toBe('https://gitlab.com?ref=@evil.example/org/repo.git');
      expect(withoutUrlUserinfo(withUserinfo('http', `alice:${SECRET}`, 'localhost#@evil.example/pkg.tgz'), reader))
        .toBe('http://localhost#@evil.example/pkg.tgz');
    }
  });

  it('for fetch, also ends the authority at `\\`; git reads a `\\` as part of the userinfo', () => {
    const url = 'http://localhost\\@evil.example/pkg.tgz';
    expect(withoutUrlUserinfo(url, 'fetch')).toBe(url);
    expect(withoutUrlUserinfo(url, 'git')).toBe('http://evil.example/pkg.tgz');
    expect(withoutUrlUserinfo(url)).toBe('http://evil.example/pkg.tgz');
    expect(withoutUrlUserinfo(withUserinfo('https', `alice:${SECRET}\\x`, 'gitlab.com/org/repo.git'), 'git'))
      .toBe('https://gitlab.com/org/repo.git');
  });

  it('masks a password that holds a raw `?` or `#`, or for fetch a `\\`, which the reader takes for a host and port', () => {
    for (const reader of ['git', 'fetch'] as const) {
      expect(withoutUrlUserinfo(withUserinfo('https', `alice:pa?${SECRET}`, 'gitlab.com/org/repo.git'), reader))
        .toBe('https://***@gitlab.com/org/repo.git');
      expect(withoutUrlUserinfo(withUserinfo('https', `alice:pa#${SECRET}`, 'gitlab.com/org/repo.git'), reader))
        .toBe('https://***@gitlab.com/org/repo.git');
      expect(withoutUrlUserinfo(withUserinfo('https', `alice:pa?${SECRET}`, 'gitlab.com'), reader))
        .toBe('https://***@gitlab.com');
    }
    expect(withoutUrlUserinfo(withUserinfo('http', `alice:pa\\${SECRET}`, 'localhost:8080/pkg.tgz'), 'fetch'))
      .toBe('http://***@localhost:8080/pkg.tgz');
    // The URL parser behind fetch rejects it, so fetch never contacts a host.
    expect(() => new URL(withUserinfo('http', `alice:pa\\${SECRET}`, 'localhost:8080/pkg.tgz'))).toThrow();
  });

  it('does not mask an `@` after an authority the reader accepts', () => {
    for (const reader of ['git', 'fetch'] as const) {
      for (const url of AT_AFTER_THE_AUTHORITY) expect(withoutUrlUserinfo(url, reader)).not.toContain('***');
    }
    expect(withoutUrlUserinfo('http://localhost:8080\\@evil.example/pkg.tgz', 'fetch'))
      .toBe('http://localhost:8080\\@evil.example/pkg.tgz');
  });

  it('for fetch, keeps the host, path, query and fragment the URL parser behind fetch reads, without credentials', () => {
    for (const url of [
      ...AT_AFTER_THE_AUTHORITY,
      'http://localhost\\@evil.example/pkg.tgz',
      withUserinfo('https', `alice:${SECRET}`, 'gitlab.com/org/repo.git'),
      withUserinfo('https', `alice:${SECRET}@x`, 'gitlab.com/org/repo.git'),
      withUserinfo('http', `alice:${SECRET}`, 'localhost?ref=@evil.example/pkg.tgz'),
    ]) {
      const parsed = new URL(url);
      const shown = new URL(withoutUrlUserinfo(url, 'fetch'));
      expect(shown.host).toBe(parsed.host);
      expect(shown.pathname + shown.search + shown.hash).toBe(parsed.pathname + parsed.search + parsed.hash);
      expect(shown.username).toBe('');
      expect(shown.password).toBe('');
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

  it('ends the authority at `?` and `#`, as git does, so an `@` after it is left alone', () => {
    for (const name of ['gitlab.com?ref=@evil.example/org/repo', 'localhost#@evil.example/org/repo']) {
      expect(scanNameWithoutUserinfo(name)).toBe(name);
    }
    expect(scanNameWithoutUserinfo(`alice:${SECRET}@gitlab.com?ref=@evil.example/org/repo`))
      .toBe('gitlab.com?ref=@evil.example/org/repo');
  });

  it('names a scan queued for a URL with an empty userinfo as a new scan of that URL is named', () => {
    expect(scanNameWithoutUserinfo('@gitlab.com/org/repo')).toBe('gitlab.com/org/repo');
    expect(scanNameWithoutUserinfo('@git.example.com:8080/repo')).toBe('git.example.com:8080/repo');
    expect(scanNameWithoutUserinfo('@@gitlab.com/org/repo')).toBe('gitlab.com/org/repo');
    // The name a new scan of `https://@gitlab.com/org/repo.git` is shared under.
    const newName = withoutUrlUserinfo('https://@gitlab.com/org/repo.git').replace(/^https?:\/\//, '').replace(/\.git$/, '');
    expect(scanNameWithoutUserinfo('@gitlab.com/org/repo')).toBe(newName);
  });

  it('keeps a name with the shape of a scoped package', () => {
    for (const name of ['@scope/pkg', '@scope/pkg@1.0.0', '@my.scope/pkg']) {
      expect(scanNameWithoutUserinfo(name)).toBe(name);
    }
  });

  it('takes time linear in the length of the name', () => {
    const name = 'a' + '@'.repeat(200_000);
    const started = performance.now();
    expect(scanNameWithoutUserinfo(name)).toBe(name);
    expect(scanNameWithoutUserinfo(name + '/x')).toBe('/x');
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});

describe('withoutUrlQueryAndFragment', () => {
  it('drops the query string, where a key passed to an endpoint lives', () => {
    expect(withoutUrlQueryAndFragment(`https://agent.example/v1/chat/completions?api_key=${SECRET}`))
      .toBe('https://agent.example/v1/chat/completions');
  });

  it('drops the fragment, with or without a query', () => {
    expect(withoutUrlQueryAndFragment('https://agent.example/v1/chat#frag')).toBe('https://agent.example/v1/chat');
    expect(withoutUrlQueryAndFragment(`https://agent.example/v1/chat?k=${SECRET}#frag`)).toBe('https://agent.example/v1/chat');
  });

  it('cuts at the first `?` or `#`, whichever comes first', () => {
    expect(withoutUrlQueryAndFragment('https://agent.example/a#b?c')).toBe('https://agent.example/a');
    expect(withoutUrlQueryAndFragment('https://agent.example/a?b#c')).toBe('https://agent.example/a');
  });

  it('keeps a URL with no query or fragment, and a string that is not a URL', () => {
    expect(withoutUrlQueryAndFragment('http://localhost:8080/v1/chat/completions')).toBe('http://localhost:8080/v1/chat/completions');
    expect(withoutUrlQueryAndFragment('unknown')).toBe('unknown');
    expect(withoutUrlQueryAndFragment('what?#')).toBe('what?#');
  });

  it('after withoutUrlUserinfo, a masked userinfo with a `?` in its password is gone before the cut', () => {
    const typed = withUserinfo('https', `alice:pa?ss${SECRET}`, 'agent.example/v1/chat?api_key=k');
    expect(withoutUrlQueryAndFragment(withoutUrlUserinfo(typed, 'fetch'))).toBe('https://***@agent.example/v1/chat');
  });
});

describe('withoutUrlUserinfo time', () => {
  it('takes time linear in the length of the URL', () => {
    const url = 'https://a' + '@'.repeat(200_000);
    const started = performance.now();
    withoutUrlUserinfo(url, 'git');
    withoutUrlUserinfo(url + '?/', 'fetch');
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});
