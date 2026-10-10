/**
 * A URL's user name and password (or token), the userinfo before `@`, are a
 * credential. `check <URL>` needs them for one thing: `git clone` of a
 * private repository. Everything else a run does with the URL (the lines it
 * prints, its `--json` document, and the name of the scan it publishes to the
 * registry or queues for a later publish) uses the URL without them.
 */

/**
 * `url` with the userinfo removed: `https://alice:token@gitlab.com/org/repo.git`
 * becomes `https://gitlab.com/org/repo.git`. Every other character is kept,
 * so a URL that carries no userinfo comes back unchanged, and a string that
 * is not `scheme://...` is returned as it is.
 *
 * The authority of a URL ends at the first `/` after `//`, and its userinfo
 * ends at an `@` before the host. Removing everything up to the LAST `@`
 * before that first `/` therefore removes the whole userinfo for any URL
 * parser. On a malformed URL it can remove more than a parser would, which
 * only shortens a printed name; it never keeps part of a credential.
 */
export function withoutUrlUserinfo(url: string): string {
  return url.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/]*@/i, '$1');
}

/**
 * The same for a scan name made from a git URL by dropping its scheme, such
 * as `alice:token@gitlab.com/org/repo`: earlier versions queued scans under
 * that name in the pending-scan file, and a later share sends the queue.
 *
 * Only a name with an `@` before its first `/`, a `/` after that `@`, and
 * something other than `@` as its first character changes. So `org/repo`,
 * `@scope/pkg`, `pkg@1.0.0` and `gitlab.com/org/repo` come back unchanged.
 */
export function scanNameWithoutUserinfo(name: string): string {
  return name.replace(/^[^/@][^/]*@(?=[^/]*\/)/, '');
}
