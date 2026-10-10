/**
 * A URL's user name and password (or token), the userinfo before `@`, are a
 * credential. `check <URL>` needs them for one thing: `git clone` of a
 * private repository. Everything else a run does with the URL (the lines it
 * prints, its `--json` document, and the name of the scan it publishes to the
 * registry or queues for a later publish) uses the URL without them.
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

const USERINFO: Record<UrlReader, RegExp> = {
  git: /^([a-z][a-z0-9+.-]*:\/\/)[^/?#]*@/i,
  fetch: /^([a-z][a-z0-9+.-]*:\/\/)[^/?#\\]*@/i,
};

/**
 * `url` with the userinfo removed: `https://<user>:<token>@gitlab.com/org/repo.git`
 * becomes `https://gitlab.com/org/repo.git`. Every other character is kept,
 * and a string that is not `scheme://...` is returned as it is.
 *
 * The userinfo is everything up to the last `@` inside the authority, as
 * `reader` ends it. An `@` after the authority, in the path, the query or the
 * fragment, is left alone, so a URL whose authority holds no `@` comes back
 * unchanged and still names the host `reader` contacts. `reader` defaults to
 * `git`, whose authority reaches at least as far as the one `fetch` reads, so
 * the default removes at least the userinfo `fetch` would find.
 */
export function withoutUrlUserinfo(url: string, reader: UrlReader = 'git'): string {
  return url.replace(USERINFO[reader], '$1');
}

/**
 * The same for a scan name made from a git URL by dropping its scheme, such
 * as `alice:token@gitlab.com/org/repo`: earlier versions queued scans under
 * that name in the pending-scan file, and a later share sends the queue.
 *
 * Only a name with an `@` before its first `/`, `?` or `#` (where git ends
 * the authority), a `/` after that `@`, and something other than `@` as its
 * first character changes, and only up to the last such `@`. So `org/repo`,
 * `@scope/pkg`, `pkg@1.0.0`, `gitlab.com/org/repo` and
 * `gitlab.com?ref=@example.com/org/repo` come back unchanged.
 */
export function scanNameWithoutUserinfo(name: string): string {
  return name.replace(/^[^/?#@][^/?#]*@(?=[^/]*\/)/, '');
}
