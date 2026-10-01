---
type: fixed
issue: 686
---
#### `engines.node` names the floor the CLI starts on (#686)

- **`engines.node` is now `^20.19.0 || >=22.12.0`, was `>=18.0.0`.** The compiled CLI is
  CommonJS and `require()`s ESM-only dependencies at startup (`@opena2a/registry-client`
  from `dist/registry/publish.js` first), which Node runs unflagged only from 20.19.0 and
  22.12.0. On anything lower every command, `--version` included, exited 1 with
  `ERR_REQUIRE_ESM`, while npm installed the package without a warning. Measured on this
  tree: `node dist/cli.js --version` exits 1 on 20.18.3 and prints the version on 20.19.0
  and 24. npm now prints `EBADENGINE` on an older Node at install time, and the README's
  Install line states the same floor. `__tests__/repo/engines-node-floor.test.ts` derives
  the requirement from the ESM-only value imports in `src/`, so a new one cannot lower it
  unnoticed.
