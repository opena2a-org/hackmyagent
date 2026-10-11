/**
 * A URL's user name and password (or token), the userinfo before `@`, are a
 * credential. `check <URL>` needs them for one thing: `git clone` of a
 * private repository. Everything else a run does with the URL (the lines it
 * prints, its `--json` document, and the name of the scan it publishes to the
 * registry or queues for a later publish) uses the URL as `withoutUrlUserinfo`
 * returns it.
 */

/**
 * The program a URL is handed to, which decides where the URL's authority
 * (the userinfo, host and port after `//`) ends. `git`, and the curl it uses
 * for http and https, end it at the first `/`, `?` or `#`. `fetch` parses a
 * URL by the WHATWG URL standard, which for http and https also ends it at
 * `\`. So `http://localhost\@example.com/` reaches example.com through git
 * and localhost through `fetch`.
 */
export type UrlReader = 'git' | 'fetch';

const AUTHORITY_ENDS: Record<UrlReader, string> = {
  git: '/?#',
  fetch: '/?#\\',
};

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/** Put in place of a userinfo the reader of the URL does not end where it ends. */
const MASK = '***';

/** The index of the first character of `s` at or after `from` that is in `chars`, or `s.length`. */
function firstOf(s: string, chars: string, from = 0): number {
  for (let i = from; i < s.length; i++) {
    if (chars.includes(s[i])) return i;
  }
  return s.length;
}

/** Whether `<scheme>//<hostPort>/` names a host (and port) a URL parser accepts. */
function isHostPort(scheme: string, hostPort: string): boolean {
  if (hostPort === '') return false;
  try {
    new URL(`${scheme}${hostPort}/`);
    return true;
  } catch {
    return false;
  }
}

/**
 * `url` with the userinfo removed: `https://<user>:<token>@gitlab.com/org/repo.git`
 * becomes `https://gitlab.com/org/repo.git`. Every other character is kept,
 * and a string that is not `scheme://...` is returned as it is.
 *
 * The userinfo is everything up to the last `@` inside the authority, which
 * ends at the first of `reader`'s end characters after `//`. An `@` after the
 * authority, in the path, the query or the fragment, is left alone, so a URL
 * whose authority holds no `@` comes back unchanged and still names the host
 * `reader` contacts. `reader` defaults to `git`, whose authority reaches at
 * least as far as the one read here for `fetch`.
 *
 * The userinfo is masked rather than removed when the last `@` before the
 * first `/` comes after the end of the authority and the host and port read
 * here (after the last `@` inside the authority, else right after `//`) are
 * not ones a URL parser accepts. Then everything between `//` and that `@` is
 * replaced with `***`. A password that holds a raw `?` or `#` (or, for
 * `fetch`, a `\`) is such a case: it ends the authority inside the userinfo,
 * so `reader` reads the rest of the user name and password as a host and
 * port, which it rejects, and `https://<user>:<pa?ss>@gitlab.com/org/repo.git`
 * is shown as `https://***@gitlab.com/org/repo.git`. A URL whose host and
 * port read here a URL parser accepts, such as
 * `https://gitlab.com?ref=@evil.example/org/repo.git`, is never masked, so it
 * still names the host that was contacted.
 *
 * `fetch` reads a `/` or `\` right after `//` as part of the `//`, and this
 * function does not: it ends the authority there. So the userinfo `fetch`
 * finds in `http://\<user>:<pw>@gitlab.com/pkg.tgz` is masked, giving
 * `http://***@gitlab.com/pkg.tgz`, and the one in
 * `http:///<user>:<pw>@gitlab.com/pkg.tgz` is kept.
 */
export function withoutUrlUserinfo(url: string, reader: UrlReader = 'git'): string {
  const scheme = SCHEME.exec(url)?.[0];
  if (scheme === undefined) return url;
  const start = scheme.length;
  const end = firstOf(url, AUTHORITY_ENDS[reader], start);
  const at = url.lastIndexOf('@', end - 1);
  const hostStart = at >= start ? at + 1 : start;
  const slash = firstOf(url, '/', start);
  const lastAt = url.lastIndexOf('@', slash - 1);
  if (lastAt >= end && !isHostPort(scheme, url.slice(hostStart, end))) {
    return scheme + MASK + url.slice(lastAt);
  }
  return scheme + url.slice(hostStart);
}

/**
 * `url` without its query and fragment: everything from the first `?` or `#`
 * after `scheme://` is dropped, so `https://host/v1/chat?api_key=k#x` becomes
 * `https://host/v1/chat`. A query is where a key is passed to an agent
 * endpoint, and the name a run sends to the registry must not carry it. A
 * string that is not `scheme://...` is returned as it is. Apply it after
 * `withoutUrlUserinfo`, whose masking reads the `?` and `#` of a password.
 */
export function withoutUrlQueryAndFragment(url: string): string {
  const scheme = SCHEME.exec(url)?.[0];
  if (scheme === undefined) return url;
  return url.slice(0, firstOf(url, '?#', scheme.length));
}

/**
 * Whether `name` has the shape of a scoped package name, `@scope/name` with an
 * optional `@version`, whose leading `@` is not an empty userinfo.
 */
function isScopedPackageName(name: string): boolean {
  return /^@[^/@:?#]+\/[^/@:?#]+(?:@[^/]*)?$/.test(name);
}

/**
 * The same for a scan name made from a git URL by dropping its scheme, such
 * as `alice:token@gitlab.com/org/repo`: earlier versions queued scans under
 * that name in the pending-scan file, and a later share sends the queue.
 *
 * Only a name with an `@` before its first `/`, `?` or `#` (where git ends
 * the authority) and a `/` after that `@` changes, and only up to the last
 * such `@`. So `org/repo`, `pkg@1.0.0`, `gitlab.com/org/repo` and
 * `gitlab.com?ref=@evil.example/org/repo` come back unchanged.
 *
 * A leading `@` is an empty userinfo, as in `@gitlab.com/org/repo` from
 * `https://@gitlab.com/org/repo.git`, which is named `gitlab.com/org/repo`
 * like a new scan of that URL. A name with the shape of a scoped package,
 * `@scope/pkg` or `@scope/pkg@1.0.0`, is left as it is, and so is the one git
 * URL name that has the same shape, `@<host>/<repo>`.
 */
export function scanNameWithoutUserinfo(name: string): string {
  const end = firstOf(name, '/?#');
  const at = name.lastIndexOf('@', end - 1);
  if (at < 0 || name.indexOf('/', at) < 0) return name;
  if (name.startsWith('@') && isScopedPackageName(name)) return name;
  return name.slice(at + 1);
}
