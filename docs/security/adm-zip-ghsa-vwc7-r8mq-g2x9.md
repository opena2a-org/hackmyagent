# GHSA-vwc7-r8mq-g2x9 (adm-zip) — known-open, with no patched version

**Verdict: not reachable through first-party code; reachable inside onnxruntime-node's postinstall under the stated conditions.**

The entry is open. It is written down here rather than gated because neither of
this repository's two advisory instruments can see a finding at this severity,
and an advisory that no instrument reports is one a reader has to be told
about in prose or not at all.

Everything the verdict rests on is stated below rather than pointed at. A
record whose evidence lives somewhere else is a record that goes stale without
anyone noticing, and the four lockfile readings at the bottom are re-checked on
every `npm test` by `__tests__/supply-chain/adm-zip-advisory-record.test.ts`:
when the lockfile stops matching them, that suite fails and names the field.
This is the rule `scripts/audit-consumer-resolution.mjs` already applies to its
own waivers — an entry that stops matching fails rather than rots — applied to
a finding that instrument's severity floor cannot reach.

## The edge into this tree

`adm-zip` is here because one package declares it, and only one:
`onnxruntime-node@1.27.0` declares `adm-zip: ^0.5.16`
(`package-lock.json:2628`). That package carries `"hasInstallScript": true`,
so its postinstall runs on a plain `npm install`.

This tree's own `overrides` block pins `adm-zip: ^0.6.0` (`package.json:69`),
which resolves `node_modules/adm-zip` to `0.6.1` here
(`package-lock.json:1244-1246`). That pin governs **this** tree and no other:
npm applies an `overrides` block only to the tree that declares it, and
`overrides` are not published, so a consumer installing `hackmyagent` resolves
`adm-zip` from `onnxruntime-node`'s own `^0.5.16` range and not from this pin.
What a consumer actually resolves is measured by
`scripts/audit-consumer-resolution.mjs`, which packs this tool and resolves the
tree a user gets; it is not asserted by this file, because this file cannot see
a consumer's tree.

## Why first-party code does not reach it

No module under `src/` imports, requires, dynamically imports or calls
`adm-zip`. That zero is held by
`__tests__/supply-chain/adm-zip-call-sites.test.ts`, which walks every `.ts`,
`.tsx`, `.js`, `.mjs`, `.cjs` and `.jsx` file in the tree, prints the size of
the set it walked, and fails naming the file and line if a call site appears.

`hma check` does unpack archives it did not author — three of its arms
download one — but it unpacks them through `src/hardening/extract-archive.ts`,
which is first-party and has no dependency on `adm-zip`.

## Where it IS reached

Inside `onnxruntime-node@1.27.0`'s postinstall, on every install:

- `script/install.js:22` requires `install-utils.js` at module top, and
  `install-utils.js:11` requires `adm-zip` at module top. Both requires
  therefore run before any early exit the script might take — the module is
  loaded whether or not the script goes on to download anything.
- The extraction itself is `install-utils.js:156` (`new AdmZip(packageFilePath)`)
  and `install-utils.js:183`
  (`extractEntryTo(zipEntry, extractDir, false, true)` — the fourth argument is
  overwrite, and it is true), into a predictable `os.tmpdir()`-rooted path
  created by a recursive mkdir.
- That extraction runs on a **default linux/x64 install**, because the cuda12
  manifest is required there and its provider is not bundled in the npm
  package, and on **any platform** under the `--onnxruntime-node-install` flag
  or the `ONNXRUNTIME_NODE_INSTALL` environment variable.
- The actor on that path is a local user of the same host: someone who can
  write the predictable temporary path the archive is unpacked into, or who
  controls what that download returns.

The `[0.27.0]` entry in `CHANGELOG.md` says of the sibling advisory
`GHSA-xcpc-8h2w-3j85` that "the base package ships those binaries, so that
script exits before requiring `adm-zip` on a default install". That sentence is
false for linux/x64 at `onnxruntime-node@1.27.0`, for the reason above; the
reading that replaces it is the one stated here.

## Why neither instrument reports it

Both of this repository's advisory gates drop everything below `high`:

- `.github/workflows/dependency-audit.yml:81` runs
  `npm audit --package-lock-only --audit-level=high`.
- `scripts/audit-consumer-resolution.mjs:139` drops the rest with
  `if (v.severity !== 'high' && v.severity !== 'critical') continue;`, and that
  script's `ALLOWED` waiver list currently holds zero entries, so there is no
  waiver row this finding could have been written into either.

The `high` floor is a decision that workflow states and argues in its own
header (`.github/workflows/dependency-audit.yml:24-28`). This record does not
revisit it.

## What this repository cannot derive

The advisory's severity, its affected range and its patched version are not
derivable from this repository. Both instruments above read a live advisory
database at the moment they run; no tracked file carries those values as
facts, and nothing offline can check them. The numbers below are therefore
carried **as a dated reading**, never as a property of the tree:

> Read on **2026-09-19**: `GHSA-vwc7-r8mq-g2x9` is `CVE-2026-76845`; severity
> medium, CVSS 3.1 6.5, `AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N`; affected
> `>= 0.5.9, <= 0.6.0`; patched version in the database: none. On the same
> date, `adm-zip` 0.6.1 was measured refusing the mechanism the advisory
> describes.

Re-read them with:

```sh
gh api /advisories/GHSA-vwc7-r8mq-g2x9 --jq '.vulnerabilities[]|select(.package.name=="adm-zip")|.first_patched_version'
```

A non-null answer from that command reopens this entry: it means upstream has
published a version to move to, and the decision recorded here — carry it,
because there is nowhere to move — no longer holds. Until then `0.6.1` is not
recorded as a remedy, only as what this tree resolves.

The readings in this file follow the ruling of `2026-09-19T18:08:05Z`.

## Lockfile readings

Four fields, re-checked against `package-lock.json` on every `npm test`. A
lockfile that stops matching any of them fails that suite and names the field
and the value the lockfile now carries.

- declarer count: `1`
- declaring path: `node_modules/onnxruntime-node`
- declared range: `^0.5.16`
- resolved version: `0.6.1`
