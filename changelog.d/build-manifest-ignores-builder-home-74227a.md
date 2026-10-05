---
type: fixed
---
- `npm run build` no longer reads the build machine's home directory when it
  writes `dist/integrity-manifest.json`. With a `.gguf` file in
  `~/.nanomind/models/`, the build added a `modelHash` of that file to the
  manifest, so the same source tree built on two machines produced two
  different manifests, and the startup self-check compared each user's own
  cached `.gguf` against the build machine's file. The manifest is now made
  from `package.json` and the files under `dist/` only, and carries no
  `modelHash`.
