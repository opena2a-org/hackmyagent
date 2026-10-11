---
type: fixed
issue: 992
---
#### `createSecretlessPlugin` is exported, and an AIM capability policy is checked before each plugin's fix step (#992)

- `require('hackmyagent').createSecretlessPlugin` was `undefined`, so the
  Built-in Plugins example in `docs/PLUGIN_API.md` failed at its import. It is
  now exported beside the other three factories, and the guide states the
  count of four that its table lists.
- The guide said plugins given an `aimCore` get capability policy checks, but
  no plugin made one. Each built-in plugin now asks the policy for
  `file:write` before its fix step. With a `policy.yaml` in the aim-core data
  directory (for `fix-all --with-aim`, the `aim/` directory of the project's
  store) that denies it, the plugin still scans and reports, applies no fix,
  and writes a `fix.denied` audit event. Without a `policy.yaml` nothing
  changes. `fixAllowedByPolicy` is exported for custom plugins.
