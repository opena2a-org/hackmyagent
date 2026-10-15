# Install

Package-manager installs, the Node.js versions the CLI needs, a build from source, the download that installing triggers and how to skip it, and how to verify a release.

## npm

```bash
npx hackmyagent secure          # run without installing
npm install -g hackmyagent      # global install
npm install --save-dev hackmyagent
```

Requires Node.js 20.19 or later on the 20 line, or 22.12 or later: the first releases that load ES modules through `require()`, which the CLI does at startup.

## Homebrew

```bash
brew install opena2a-org/tap/hackmyagent
```

## From source

[CONTRIBUTING.md](../CONTRIBUTING.md) has the development loop and what happens to a pull request opened from a fork.

```bash
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent && npm install && npm run build && npm test
node dist/cli.js secure      # run the build from source
```

## Install-time download, and how to skip it

Installing this package runs the install script of `onnxruntime-node`, the dependency this tool uses for local NanoMind inference. On Linux x64 that script downloads an execution-provider package, `Microsoft.ML.OnnxRuntime.Gpu.Linux`, from nuget.org: about 236 MB at `onnxruntime-node` 1.30.0, the release a fresh install resolved on 2026-09-19. This tool does not use that provider: it requests no execution provider anywhere, so the CPU provider is the only one it runs. The check is `grep -rn "executionProviders" src/`, which prints nothing and exits 1, read on 2026-09-20.

To install without that download, set `ONNXRUNTIME_NODE_INSTALL=skip` in the environment of the install command, or run `npm config set onnxruntime-node-install skip` once so that every later install skips it. The CPU runtime this tool uses ships inside the npm package itself: at 1.27.0, `bin/napi-v6/linux/x64` carries `libonnxruntime.so.1` and `onnxruntime_binding.node`, read on 2026-09-20.

`--ignore-scripts` is safe for a CI install of this package: this tree carries exactly one non-dev dependency that declares an install script, `onnxruntime-node`. In `package-lock.json`, exactly one `"hasInstallScript": true` entry has no `"dev": true` beside it, and it is `node_modules/onnxruntime-node`, read on 2026-09-20.

## Verifying what was installed

Every release publishes via npm Trusted Publishing with SLSA v1 provenance. No long-lived `NPM_TOKEN`. GitHub Actions exchanges its OIDC token with npm at publish time.

```bash
npm view hackmyagent dist.attestations --json
# Expects non-empty result with predicateType "https://slsa.dev/provenance/v1"
```
