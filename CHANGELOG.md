# Changelog

All notable changes to HackMyAgent are documented in this file.

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
