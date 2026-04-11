# Changelog

All notable changes to HackMyAgent are documented in this file.

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
