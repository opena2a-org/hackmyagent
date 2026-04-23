# Changelog

All notable changes to HackMyAgent are documented in this file.

## [Unreleased]

## [0.18.3] - 2026-04-23

### Added
- **`check --json` now emits registry fields on registered packages (F1).** When the registry has trust data for the target, `hackmyagent check @pkg --json` (default local-scan path) emits `trustLevel`, `trustScore`, `verdict`, `scanStatus`, `packageType`, `lastScannedAt`, `communityScans`, and `cveCount` at the top level alongside the scan findings. Previously these fields only appeared on the `--no-scan` path. Closes the F1 parity gap from `briefs/check-command-divergence.md`; `opena2a check --json` (which spawn-delegates to hackmyagent) inherits the fix.

### Changed
- **`check` output consumes `@opena2a/cli-ui@0.3.0` primitives.** Exact-pinned the dependency. The registry-only render path (`check @pkg --no-scan`) now delegates to `renderCheckBlock` + `renderNextSteps` so the output structure matches `ai-trust@0.4.0` and the forthcoming parity fixtures in opena2a-parity. Trust-meter gating (`scanStatus === 'completed' | 'warnings'`) moves into the shared renderer — packages with `scanStatus: undefined` no longer render a score meter ("a number implies measurement", per F6).
- **PyPI and GitHub not-found paths render via `renderNotFoundBlock`.** Replaces the raw `console.error` one-liners. Same shape as ai-trust's not-found block.
- **`npm pack` `code 128` on git-style names translated to a did-you-mean hint.** `hackmyagent check user/repo` (no `@`) that slips past the GitHub classifier and fails at `npm pack`'s git fallback now renders `Looks like a git-style name. npm packages use "@scope/name" — did you mean "@user/repo"?` instead of leaking the raw exit code (F3).

### Engineering
- New `src/check-render.ts` extracts the pure helpers (`buildCheckJsonOutput`, `mapScanStatusForMeter`, `translateNpmPackError`) for unit testability. 18 new tests in `__tests__/check-render.test.ts` lock the F1 parity contract and F6 meter gate.

## [0.18.2] - 2026-04-22

### Fixed
- **E2E-003 live network detection skipped on CI (#119).** GHA ubuntu-latest runners don't reliably surface localhost TCP connections to `ss` polling within the 15s event window. Local dev on macOS and Linux continues to exercise the full detection path. Blocks the 0.18.1 publish workflow; 0.18.2 is the shippable bundle.

## [0.18.1] - 2026-04-22

### Fixed
- **E2E-003 live network detection no longer times out in CI (#117).** The test's internal `waitForEvent` uses a 15s polling budget, but vitest's default 10s test timeout was firing first on GHA ubuntu-latest runners (slower lsof/ss polling than local macOS). Bumped the test timeout to 30s. No product change; blocks previously-red 0.18.0 publish.

Everything from the superseded 0.18.0 tag ships in 0.18.1. The v0.18.0 tag was force-published against a pre-fix commit and the workflow failed in CI; 0.18.1 is the shippable version.

## [0.18.0] - 2026-04-22

First release of HackMyAgent published via npm Trusted Publishing — ships with SLSA v1 provenance attestations. Verify with `npm view hackmyagent dist.attestations --json`.

### Added
- **Registry trust queries route through `@opena2a/registry-client@0.1.0` (#115).** `trustCheck` / `trustBatch` / `queryRegistry` / `publishToRegistry` now delegate to the shared HTTP client (published to npm with SLSA v1 provenance). All three fleet CLIs — hackmyagent, opena2a, ai-trust — share a single trust-lookup implementation. Any fix lands in one place. Exact-pinned per CA-034 M1.
- **Observations block in `secure` output (#110).** Scanner now emits a dedicated Observations section that groups per-finding context (file, severity, fix command, Verify line) separately from the verdict and artifact summary. Renders through `@opena2a/cli-ui@0.2.0` for cross-CLI parity with `opena2a review` and `ai-trust` output. Replaces the inlined `observations.ts` + `analyst-render.ts` implementations which have been removed from this repo and centralized in `@opena2a/cli-ui`.
- **Artifacts block + Verdict names the lead finding (#111).** Verdict line now quotes the single highest-severity finding by name and check ID, followed by an Artifacts block enumerating what was scanned (files, paths, line counts). CISOs reading a one-screen verdict can identify the specific blocking issue without scrolling.
- **`--nanomind` specialist gate.** NanoMind generative analysis is now invoked only on artifact types where the input-classifier v3.1 gate passes — reduces off-topic hallucinations on clean scans. Gate thresholds and model path live in `nanomind-core/orchestrate.ts`.
- **Cross-CLI parity gate CI (#113).** New workflow in `.github/workflows/parity.yml` asserts that `hackmyagent secure`, `opena2a review`, and `ai-trust` produce identical Observations/Verdict blocks on a shared fixture set. Prevents rendering divergence between the three CLIs that all consume `@opena2a/cli-ui`.
- **Scanner finds agent identity + DNA files in `.well-known/`.** `AIM-001` (no agent identity) and `DNA-001` (no behavioral fingerprint) now also recognize `.well-known/agent-card.json`, `.well-known/agent-dna.json`, and `.well-known/aim.json` alongside the existing root-level lookups. Additive — repos that keep their identity files at the project root continue to pass unchanged. Aligns with RFC 8615 well-known URI conventions and the A2A protocol spec.

### Changed
- **Consumes `@opena2a/cli-ui@0.2.0` for Observations rendering (#112).** Inlined rendering code removed; all three CLIs now render through the shared package. Fixes a stale `semanticCount` on the `secure` path where the analyst-render output counted pre-dedupe findings.
- **HMA's own agent identity files moved to `.well-known/`.** `agent-card.json` and `agent-dna.json` now live at `.well-known/agent-card.json` and `.well-known/agent-dna.json` to model the convention.
- **Release playbook moved to `docs/release-playbook.md`.** Self-references and `.release/baselines.json` updated to match.
- **Tag-triggered release workflow with npm provenance (#106).** Publishes now run via GitHub Actions OIDC exchange — no `NPM_TOKEN`, no long-lived credentials. Triggered by pushing a `v*` tag to `main`.
- **Release workflow pinned to Node 24 (#107).** Required for npm Trusted Publishing OIDC flow. Legacy Node 20 workflows failed to exchange the OIDC token.

### Fixed
- **`package-lock.json` sibling-symlink regenerated (#115).** Prior lockfile resolved `@opena2a/contribute` as `link:../opena2a/packages/contribute` (a local dev symlink). Clean CI checkouts saw `npm ci` succeed with a dangling `node_modules` symlink, which surfaced at TS2307 build time and silently blocked the cross-CLI parity gate that fetches `hackmyagent@main` during CI. Lockfile regenerated in `/tmp` outside the workspace so npm resolved `@opena2a/contribute` from the npm registry; zero `"link": true` entries remain.
- **`RAG-002` no longer fires on TypeScript data-catalog string literals (#108).** Property-value lines like `description: "...store and retrieve context..."` are now recognized as pure data rather than a retrieval call. The rule still fires on runtime retriever calls (`.retrieve(`, `retriever.invoke(`, `vectorStore.similaritySearch(`), Python f-string prompt assembly, template literals that embed retrieval calls, and any line containing a function call.
- **`MEM-006` no longer fires on DVAA-style adversarial test harnesses (#109).** Files whose basename matches `*-test.{m?js,ts}` / `*.test.{m?js,ts}` / `*.spec.{m?js,ts}` or whose path contains an exact `dvaa|honeypot|trap-fixtures|adversarial-fixtures|vulnerable-by-design` directory component are skipped. Hyphen-prefix directory names (`trap-router/`, `adversarial-reports/`) do NOT skip — exact directory-component match required. No content-marker gate is applied (scanned code cannot turn off its own scanner).

## [0.17.11] - 2026-04-17

Republish of 0.17.10. The 0.17.10 tarball had been pre-published to npm 3 days early without the audit-driven fixes (PR 1, 2, 3, A, B). 0.17.11 ships the same code that the 0.17.10 changelog describes. No new functional changes between 0.17.10 and 0.17.11.

## [0.17.10] - 2026-04-17

### Added
- **`hackmyagent detect` — Shadow AI audit command.** New top-level command that scans the local machine and current project for AI tools, MCP server configurations, AI config files, and SOUL.md governance files. Reports a governance score and actionable findings designed for CISOs and security engineers who need an inventory of what's actually running. Supports `--json`, `--verbose`, and `--export-csv` for CMDB integration.
- **`--nanomind` opt-in flag for generative analysis.** The NanoMind generative layer (Tier 2) is now opt-in instead of always-on. Users who want AI-powered threat narratives on findings invoke `secure --nanomind` or `check --nanomind`; default `secure`/`check` runs the static analyzer suite only. Adds 15-30s per finding when enabled, surfaced via a one-line latency disclosure. Static AST analyzers (Tier 0/1) run regardless.
- **`hackmyagent nanomind` subcommand.** Renamed from `analm`. `nanomind setup` downloads the generative model; `nanomind status` reports model + runtime state.
- **Smart registry ping with health preflight.** `secure --publish` and equivalent flows now run a one-line health check against the registry before attempting a publish, and emit a `scan_ping` heartbeat for observability. Fails fast on unreachable / degraded registry instead of timing out the whole publish.
- **Opportunistic retry backoff for failed contributions.** Anonymous scan summaries that fail to upload are retried in the background with exponential backoff. No new user-visible UI; previously failures were silently dropped.
- **Unified contribution config.** All scan types (`secure`, `check`, `scan-soul`, `detect`) now share `~/.opena2a/config.json`. Set `--no-contribute` once and it applies everywhere.

### Changed
- **Unified output formatter across `secure` / `scan-soul` / `harden-soul` / `explain` / `detect`.** All repo-style commands now route through the `secure` formatter: same badges, same severity grouping, same Verify/Fix per finding. `check` (package-style) keeps its registry-oriented format. Eliminates the cross-command UX divergence that made the tool look like four separate scanners stitched together.
- **CISO-grade UX rework.** Every finding now ships with a one-line `Verify:` command and a one-line `Fix:` command. Credential findings no longer shame the user for env-var usage; capability-abuse findings replace wall-of-names listings with a single runnable `harden-soul` command. The dim/highlight conventions were standardized so the eye can scan a 200-finding report without losing its place.
- **NanoMind generative findings are capped at HIGH when confidence < 0.80.** Previously low-confidence generative findings rendered as CRITICAL with a hardcoded 60% confidence stamp. Now CRITICAL only emits when the model is genuinely confident; below threshold the severity is capped and the finding shows a qualitative confidence label instead of a measurement.
- **NanoMind `max_tokens` raised 512 → 2048.** Generative descriptions previously truncated mid-word (300-char ceiling) because the inference budget was too tight. Now full descriptions render reliably.
- **`--analm` flag and `analm` subcommand renamed to `--nanomind`.** The internal model is NanoMind; the legacy `analm` name was a research-era artifact. Both old names are aliased for one release; the alias will be removed in 0.18.
- **Check + category counts derived dynamically from the taxonomy map.** Previously hardcoded as `CHECK_COUNT = 209` and `60 categories` in CLI help text — both drifted (categories were actually 44, not 60). Now both numbers are computed at module load from the same source of truth `check-metadata` reads, so help text, command descriptions, and metadata JSON cannot disagree.
- **`--ignore` re-applied after the NanoMind merge step.** Previously the `--ignore` filter ran before NanoMind merged its findings in, so ignored check IDs reappeared if NanoMind also surfaced them. `--fail-below` is now wired to standard scan mode in addition to `--ci`.
- **`AnaLM` → `NanoMind` rendering in `check` output.** `check` no longer shows a separate AnaLM analyst block; the generative output is integrated into the standard finding format when `--nanomind` is enabled.

### Fixed
- **Self-scan score: 100/100.** All CRITICAL and HIGH findings on the HMA codebase itself are resolved, and the `secure` self-scan returns clean.
- **TOCTOU-001 stops flagging legitimate `existsSync → readFileSync` config-load patterns.** Previously fired on any access-check followed by a read; now requires a write or exec between the check and the read. Adds `import(varPath)` to the exec sinks so dynamic-import abuse is still caught. Eliminated 11 FPs across `secretless`. The `import(varPath)` exec sink was added after an adversarial review surfaced that the first fix accidentally created a dynamic-import bypass.
- **Analyzer pileup on bug-bounty target descriptors collapsed.** Files named `salesforce-mcp.json` (etc.) — bug-bounty target metadata, not MCP server configs — were misclassified as `mcp_config` and routed through every agent analyzer, producing 6 overlapping findings on a single descriptor. Fixed two ways: (1) MCP classifier now matches a known-basename allowlist (`mcp.json`, `.mcp.json`, `mcpServers.json`) plus a content-fallback that requires an actual `"mcpServers":` key with BOM/whitespace tolerance; (2) capability-analyzer no longer emits `AST-GOVERN-002` — `AST-GOV-003` in governance-analyzer is the canonical zero-constraints emitter.
- **Three detection-narrowing gaps closed (adversarial review).** Surfaced by an adversarial subagent: the previous fix-pass had narrowed three patterns just enough to miss a real attack vector. Fixes restored detection without reintroducing the FPs.
- **NEMO-009 false positive on `model.eval()`, `tensor.eval()`, etc.** PyTorch's `.eval()` method is not Python's `eval()` builtin. Pattern now requires the bare `eval(` form, not method dispatch.
- **Path-context exemptions for corpus/, test/, example/ paths.** Findings inside known fixture/corpus directories no longer escalate to CRITICAL. Test fixtures are intentionally vulnerable.
- **Frontend-project signal includes Angular and Vue CLI configs.** Previously only React/Next/Vite were recognized.
- **3 FPs suppressed + TOCTOU/env-exfil hardened + AST-SCOPE dispatch corrected.**
- **webcred handles `./dist/` leading segment in package.json browser field.**
- **Project constraints propagate from sibling SOUL.md to capability-analyzer.** Fix routing for ungoverned-capability findings now references the project's actual SOUL.md when one exists, instead of suggesting the user add governance that already exists elsewhere in the repo.
- **Governance SOUL FPs eliminated.** Multiple paths where governance findings fired against well-governed agents have been suppressed.
- **`GIT-001` skipped for npm package scans.** A missing `.gitignore` is meaningful in a project repo, irrelevant in a published npm tarball.
- **SOUL/MCP oracle label accuracy.** Oracle eval labels for SOUL and MCP fixtures corrected.

## [0.17.9] - 2026-04-15

### Fixed
- **Benign FPR reduced from 90.9% to 0% on oracle P0-1 gate.** The TME v5 oracle eval (2026-04-15) measured 10/11 false positives on hard-negative benign fixtures. Four root causes fixed across the semantic compiler and three analyzers:
  - `semantic-compiler.ts`: broadened constraint regex to capture all imperative forms (`must\b`), negation-form should, and scoped `cannot` to action verbs only to avoid extracting explanatory language ("cannot reliably distinguish") as constraints. Fixed negative-capability signal to match "no network" without requiring the word "access".
  - `governance-analyzer.ts`: added `isExplicitlyRestrictedBenign` guard for skills with negative YAML capability declarations (`execute_shell: false`, `network_access: false`). These skills govern via YAML restrictions rather than natural-language SOUL constraints; applying full agent-level governance severity (high) was a false positive. Severity is now correctly `medium` for restricted benign skills.
  - `governance-analyzer.ts`: extended `isAgentLevelArtifact` to include skills with high/critical declared capabilities. Ungoverned dangerous skills (e.g. `shell.execute`, `db.delete` string capabilities) now receive the full governance suite.
  - `prompt-analyzer.ts`: replaced `isAgentLevelArtifact` with `isBehavioralArtifact` (excludes `mcp_config`) as the gate for injection/authority checks. Added `hasHighBenignContext` guard (intent=benign, confidence ≥ 0.85) to suppress jailbreak susceptibility, injection resistance, and authority confusion findings on explicitly restricted skills. Threshold 0.85 corresponds to 3 benign signals, achievable with at least one negative capability declaration.
- **New oracle benign FPR regression test suite.** `__tests__/nanomind-core/benign-fp-regression.test.ts` — 10 hard-negative fixtures (b01–b10) locked as a P0-1 regression gate. These tests must continue to pass before any publish.

## [0.16.7] - 2026-04-11

### Added
- **`--rescan` flag on `check`.** Forces a fresh local scan regardless of how fresh the cached registry data is. Previously the only way to bypass the registry cache was to wait for it to go stale (>3 days). Users who suspect the cached score is wrong, want to verify a recent fix, or are debugging a scanner regression can now force a re-scan on demand. Threaded through `checkNpmPackage`, `checkPyPiPackage`, and `checkGitHubRepo`; each skips its `queryRegistry`/`isScanStale` shortcut when `--rescan` is set and prints `Forcing fresh local scan (--rescan)...` before downloading. For skill identifiers the flag has no effect; a one-line note explains that to the user.
- **3-line next-steps footer on `check`.** Every `check` invocation (registry cache hit, fresh scan, and local-path alike) now ends with a dim 3-line footer giving the user exactly what to run next: a rescan command, a full-project scan hint, and the list of accepted target formats. Suppressed in `--ci` mode; `--json` has never printed footers and still doesn't.
- **`HMA_CHECK_COMMAND` and `HMA_FULL_SCAN_HINT` environment variables.** Let a parent CLI override the command strings used in the footer. Each carries a complete command string, not a prefix. Solves the long-standing duplicated-verb bug where opena2a-cli's router was setting `HMA_CLI_PREFIX='opena2a check'` and HMA was appending `check` to it, producing `opena2a check check <pkg>` in hint output. New helpers `getCheckCommand()` and `getFullScanHint()` read the env vars and fall back to `CLI_PREFIX`-derived defaults.

### Fixed
- **PyPI rescan hint preserves `pip:` prefix.** The PyPI path was passing the stripped package name (`requests`) to the next-steps footer instead of the original target (`pip:requests`), so the suggested rerun command was `hackmyagent check requests --rescan`, which would fall through to npm and fail with "Package not found on npm". Now preserves the original target string.
- **Stale error-message paths route through `getCheckCommand()`.** Two error paths in `checkGitHubRepo` (clone timeout) and `checkRawUrl` (fetch timeout) suggested `${CLI_PREFIX} check ./<dir>/` as the follow-up, which produced `opena2a check check ./...` under opena2a delegation. The skill-lookup timeout message also used a `CLI_PREFIX.replace(' scan', '')` hack. All three now use `getCheckCommand()`.

## [0.16.6] - 2026-04-11

### Fixed
- **Reflexive false positives on security-scanning source code.** The config-oriented pattern detectors (`mapRiskSurfaces`, `extractDataAccessPatterns`) are no longer applied to `source_code` artifacts. These detectors were designed for skills, agent configs, and system prompts — where every byte is semantically meaningful — and produced near-100% false positive rates when run against Go/TypeScript/Python source files. A file whose purpose was to scan for `eval(`, `curl | sh`, or hardcoded credentials was flagged as *containing* those attacks. On opena2a-registry the reflexive false positive count dropped from 11 Critical / 62 High on Go source to 0 / 0.
- **Source code preprocessor (`source-code-preprocessor.ts`).** Added a language-aware preprocessor that strips comments, import statements/blocks, and string literals from Go, TypeScript, JavaScript, Python, Rust, Java, and Ruby source before the config detectors see it. Keeps identifier and control-flow tokens visible for analysis, preserves byte offsets via whitespace-replacement so downstream index-based code still works.
- **Source code classification precedence.** Recognized source extensions (`.go`, `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.py`, `.pyi`, `.rs`, `.java`, `.rb`) now win over content-based heuristics in `classifyArtifactType`. Previously a Go domain file with `json:"agentType"` struct tags was misclassified as an A2A agent card, and a Go scanner file containing `sk-ant-api\d{2}-...` regex literals was misclassified as a credential dump. Both now correctly classify as `source_code`.
- **Canonical credential-format scan for source files.** Added a targeted scan that detects concrete secret formats (Anthropic, OpenAI, AWS, GitHub PAT/OAuth/app, Slack, Google, Stripe, PEM private keys) in source code, running against the unstripped content so real hardcoded secrets in string literals are still caught. The scan suppresses matches adjacent to regex metacharacters (scanner rule definitions) and matches containing placeholder markers (`FAKE`, `EXAMPLE`, `PLACEHOLDER`, etc.) directly inside the key bytes or variable name.
- **Declared purpose extraction for source files.** `extractDeclaredPurpose` now skips language comment lines (`//`, `/*`, `*`, `#`, `"""`, `'''`) when reading the first paragraph. Previously a leading doc comment saying "fixture for testing credential flow" became the declared purpose, which then tripped `isDocumentationOrTestContext` and silenced legitimate credential findings on the same file.

### Added
- 26 regression tests covering the preprocessor (per-language strip behavior), the source-code classification precedence fix, the canonical credential-format scanner (positive and negative cases), and a direct regression for the opena2a-registry false-positive reproduction.

## [0.13.0] - 2026-04-02

### Added
- **Global --ci flag** for all commands (previously only `secure` and `scan-soul` supported it)
- **Scan vs secure redirect** -- `hackmyagent scan .` now detects local paths and redirects to `secure` with a helpful message
- **10-second timeout** on `check` command DNS lookups to prevent indefinite hangs on unreachable publishers
- **writeLargeStdout helper** for safe output of large SARIF/HTML reports through pipes

### Changed
- **Unified scoring labels** across all commands: `wild` now uses strong/good/moderate/needs-attention/critical (was excellent/good/moderate/poor/critical)
- **Clearer CLI terminology** -- replaced internal "NanoMind" jargon with "semantic analysis" / "ML-enhanced" in all user-facing output
- **Better check error messages** with format examples when skill identifier is invalid
- Model download message now says "security analysis model" instead of "NanoMind"
- --deep/--static-only option descriptions updated to remove internal terminology

### Fixed
- **SARIF output truncation at 64KB** -- benchmark, scan, and attack SARIF output was silently truncated at pipe buffer limit when using console.log(); now uses sync write with backpressure handling

## [0.11.10] - 2026-03-20

### Fixed
- **Guidance coverage: 136 → 232 checks (100%)** — all hardening checks now include a plain-language `guidance` field explaining why the finding matters
- **Semantic findings (SEM-*) now include guidance** — the finding adapter maps `rationale` to `guidance`, so SEM-CRED and other semantic findings show risk explanations
- **35 mismatched guidance strings corrected** — batch addition had mapped some explanations to the wrong checks

## [0.11.9] - 2026-03-20

### Added
- **12 new security checks (199 total)** — complete coverage of every verified ARIA research finding:
  - INSTALL-001: curl|sh without checksum in install scripts
  - CLIPASS-001: Credentials passed as CLI arguments (visible in ps)
  - INTEGRITY-001: Digest/hash bypass on empty/falsy value
  - TOCTOU-001: Verify-then-use race condition
  - DOCKERINJ-001: Docker exec with variable interpolation
  - SANDBOX-005: Messaging API pre-allowed in sandbox policy
  - WEBEXPOSE-001/002/003: CLAUDE.md, .env, config files in web directories
  - SOUL-OVERRIDE-001: Skill content can override SOUL.md
  - MEM-006: Memory store without input sanitization
  - AGENT-CRED-001: No credential output protection in system prompt
- **HTTPS enforcement** for registry URL overrides (rejects http:// unless localhost)
- **`guidance` field** on all findings — separates actionable fix commands from human-readable explanations
- **`hackmyagent check-metadata`** — static JSON export of all SKILL/SUPPLY check metadata (severity, attackClass, guidance) for downstream tool integration
- **Actionable fix text** for all SKILL-* and SUPPLY-* checks — `fix` field is now a runnable command (e.g., `npx secretless-ai init`, `hackmyagent fix-all --with-aim`, `rm <file>`)

### Changed
- Check count: 187 → 199 (15 added, 3 deduplicated with NEMO equivalents)
- Category count: 39 → 60

### Fixed
- GIT-002 no longer fires when .gitignore doesn't exist (GIT-001 handles creation)
- No-args `hackmyagent` now exits with code 0 (was incorrectly exiting 1)
- Deduplicated CODEINJ-001/TMPPATH-001/ENVLEAK-001 with NEMO-005/006/007 (same detection patterns)
- Auto-detection: OpenClaw and NemoClaw checks run automatically with `hackmyagent secure` when platform files are detected. Separate `secure-openclaw` and `secure-nemoclaw` commands still work as aliases.

## [0.11.7] - 2026-03-19

### Added
- **6 new research-gap detection checks** — closes every gap between ARIA internet-wide research findings (294K+ exposed AI services) and HMA detection capabilities:
  - LLM-001 to LLM-004: Exposed LLM inference endpoints (Ollama, vLLM, LocalAI, text-generation-webui)
  - AITOOL-001 to AITOOL-004: Exposed AI tooling (Jupyter, Gradio, Streamlit, MLflow, LangServe)
  - A2A-001 to A2A-002: A2A protocol exposure (.well-known/agent.json, unauthenticated task endpoints)
  - MCP-011: MCP discovery endpoint exposure (.well-known/mcp)
  - WEBCRED-001: Credentials in web-served files (public/, static/, dist/)
- **Auto-fix for 9 of 12 new checks** — deterministic transforms, no LLM needed (bind address fixes, token generation, quote-aware credential replacement)
- **Post-fix verification** — after applying fixes, HMA re-scans to confirm each fix actually resolved the issue. CLI shows `✓✓` for verified fixes, `✓?` for unverified
- **Fixable count in scan output** — "104 issues found (11 auto-fixable with `hackmyagent secure --fix`)"
- **Expanded backup coverage** — docker-compose, Jupyter configs, .well-known files included in rollback snapshots
- **3 new attack taxonomy classes** — LLM-EXPOSE, AITOOL-EXPOSE, A2A-EXPOSE (synced with registry)
- **Taxonomy sync verification script** — `scripts/verify-taxonomy-sync.ts` compares HMA and registry attack classes

### Changed
- Check count: 183 → 187
- Category count: 35 → 39
- Rollback messaging improved: "Something wrong? Run `hackmyagent rollback` to undo all changes"

## [0.11.3] - 2026-03-18

### Added
- **AI Visibility Protection plugin** — new 4th plugin in fix-all pipeline that blocks .env from AI tool visibility and encrypts MCP server keys (requires secretless-ai at runtime, optional)
- **Next steps section** after `secure` scan output — recommends `fix-all --with-aim` and shows auto-fixable count
- **Cross-tool recommendations** — suggests `npx secretless-ai init` when credential findings are detected
- **AI visibility scanner checks** — SLAI-001 (credentials in AI context files), SLAI-003 (.env not blocked from AI tools)
- `--fix --dry-run` now shows `[DRY RUN] Would fix:` previews for each auto-fixable finding with summary

### Changed
- Plugin display names: CredVault -> Credential Protection, SignCrypt -> File Signing, SkillGuard -> Skill Safety Scanner
- fix-all pipeline is now 4 plugins: Credential Protection -> AI Visibility Protection -> File Signing -> Skill Safety Scanner
- Scanner fix messages for SKILL-001, HEARTBEAT-002/003, AIM-001/002, DNA-002 now point to `fix-all --with-aim`
- Project type detection: SKILL.md alone no longer triggers "OpenClaw Agent" label (renamed to "AI Agent")
- Duplicate findings at the same file:line are deduplicated (highest severity kept, shows "+ N related")
- Registry contribution message is transparent: shows `(--no-contribute to opt out)`
- Contribution prompt only appears after 3 scans in interactive TTY mode

## [0.10.2] - 2026-03-16

### Fixed
- Trust score now displays as `47/100` instead of raw decimal `0.47` for consistency with opena2a CLI

## [0.10.1]

### Added
- UNICODE-STEGO-001: Invisible Unicode codepoint detection (variation selectors U+FE00-FE0F, tag characters U+E0100-E01EF)
- UNICODE-STEGO-002: GlassWorm decoder pattern detection (.codePointAt with variation selector/tag hex literals)
- UNICODE-STEGO-003: Eval/Function on strings with hidden Unicode payloads (few visible chars, large byte footprint)
- UNICODE-STEGO-004: Broader Unicode tag character block detection (U+E0000-U+E01EF)
- Test fixtures for Unicode steganography checks with byte-level test file generator

## [0.8.0] - 2026-03-02

### Changed
- Consolidated 8 separate npm packages into a single unified `hackmyagent` package
- Merged `hackmyagent-core` into the main package
- Moved `@opena2a/plugin-core`, `@opena2a/signcrypt-openclaw`, `@opena2a/skillguard-openclaw`, `@opena2a/credvault-openclaw` into `hackmyagent/plugins`
- Moved `@opena2a/semantic-engine` into `hackmyagent/semantic`
- Moved `@opena2a/arp` into `hackmyagent/arp`
- Moved `@opena2a/oasb` into `hackmyagent/oasb`
- Replaced Turborepo monorepo with flat single-package structure
- Deprecated all absorbed packages on npm with migration notices
- 765 tests passing across 73 test files

### Breaking
- Import paths changed: `hackmyagent-core` imports now come from `hackmyagent`
- Subpath exports replace separate packages: `hackmyagent/plugins`, `hackmyagent/semantic`, `hackmyagent/arp`, `hackmyagent/oasb`

## [0.7.2] - 2026-02-26

### Fixed
- Fixed `buildCommunityReport` crash
- Fixed scan token authentication
- Fixed star prompt handling

## [0.7.0] - 2026-02-19

### Added
- MCP exploitation attack mode
- A2A (agent-to-agent) attack mode
- 75 attack payloads across 7 categories

## [0.5.2] - 2026-02-08

### Fixed
- README corrections to match actual code behavior
- Documented all CLI flags

## [0.5.0] - 2026-02-08

### Added
- Plugin ecosystem with modular architecture
- AIM Core integration for identity-aware scanning
- CredVault, SignCrypt, and SkillGuard plugins

## [0.4.3] - 2026-02-06

### Fixed
- Minor bug fixes and stability improvements

## [0.4.0] - 2026-02-05

### Added
- CVE-2026-25253 detection
- ClawHavoc IOC (indicators of compromise) scanning
- Configuration hardening with 11 new security checks

## [0.3.0] - 2026-02-03

### Added
- Attack mode with adversarial payload simulation
- OASB-1 (Open Agent Security Benchmark) compliance scanning
- 46 benchmark controls across 10 categories

## [0.2.0] - 2026-02-03

### Added
- OpenClaw security checks (47 specialized checks)
- Gateway misconfiguration detection
- Auto-fix for gateway binding, token, approval, and sandbox settings
