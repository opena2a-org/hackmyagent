/**
 * Attack Taxonomy Mapping
 * Maps HMA security check IDs to registry attack class identifiers.
 * These identifiers match the attack_classes table in the OpenA2A Registry.
 */

import type { SecurityFindingDraft } from './security-check';

/** Maps HMA check ID prefixes and exact IDs to attack class identifiers */
const TAXONOMY_MAP: Record<string, string> = {
  // SOUL series
  'SOUL-TH-001': 'SOUL-POISON',
  'SOUL-TH-002': 'SOUL-POISON',
  'SOUL-TH-003': 'SOUL-DRIFT',
  'SOUL-TH-004': 'SOUL-DRIFT',
  'SOUL-TH-005': 'SOUL-IMPERSONATE',
  'SOUL-CB-001': 'SOUL-BOUNDARY',
  'SOUL-CB-002': 'SOUL-BOUNDARY',
  'SOUL-IH-001': 'SOUL-INJECT',
  'SOUL-IH-002': 'SOUL-INJECT',
  'PROMPT-001': 'SOUL-INJECT',
  'PROMPT-002': 'SOUL-INJECT',
  'PROMPT-003': 'SOUL-INJECT',
  'PROMPT-004': 'SOUL-INJECT',
  'SOUL-DH-001': 'SOUL-DELEGATE',
  'SOUL-DH-002': 'SOUL-DELEGATE',
  'SOUL-HB-001': 'PHANTOM-SOUL',
  'SOUL-HB-002': 'PHANTOM-SOUL',
  'SOUL-AS-001': 'SOUL-FORK',
  'SOUL-AS-002': 'SOUL-FORK',
  'SOUL-HT-001': 'SOUL-FORK',
  'SOUL-HT-002': 'SOUL-FORK',
  'SOUL-HO-001': 'SOUL-HIJACK',
  'SOUL-HO-002': 'SOUL-HIJACK',

  // Harm avoidance
  'SOUL-HV-001': 'SOUL-HV-001',
  'SOUL-HV-002': 'SOUL-HV-002',
  'SOUL-HV-003': 'SOUL-HV-003',
  'SOUL-HV-004': 'SOUL-HV-004',

  // Credential exposure
  'CRED-001': 'RETROACTIVE-PRIV',
  'CRED-002': 'RETROACTIVE-PRIV',
  'CRED-003': 'RETROACTIVE-PRIV',
  'CRED-004': 'RETROACTIVE-PRIV',

  // Unicode steganography
  'UNICODE-STEGO-001': 'UNICODE-STEGO',
  'UNICODE-STEGO-002': 'UNICODE-STEGO',
  'UNICODE-STEGO-003': 'UNICODE-STEGO',
  'UNICODE-STEGO-004': 'UNICODE-STEGO',
  'UNICODE-STEGO-005': 'UNICODE-STEGO',

  // OpenClaw persistence
  'HEARTBEAT-001': 'HEARTBEAT-RCE',
  'HEARTBEAT-002': 'HEARTBEAT-RCE',
  'HEARTBEAT-003': 'HEARTBEAT-RCE',
  'HEARTBEAT-004': 'HEARTBEAT-RCE',
  'HEARTBEAT-005': 'HEARTBEAT-RCE',
  'HEARTBEAT-006': 'HEARTBEAT-RCE',
  'SKILL-002': 'HEARTBEAT-RCE',
  'SKILL-003': 'HEARTBEAT-RCE',

  // Skill exfiltration
  'SKILL-006': 'SKILL-EXFIL',
  'NET-001': 'SKILL-EXFIL',
  'NET-002': 'SKILL-EXFIL',
  'NET-003': 'SKILL-EXFIL',

  // Supply chain
  'SUPPLY-001': 'ORG-SKILL-SPREAD',
  'SUPPLY-002': 'ORG-SKILL-SPREAD',
  'SUPPLY-003': 'ORG-SKILL-SPREAD',
  'SUPPLY-004': 'ORG-SKILL-SPREAD',
  'SUPPLY-005': 'ORG-SKILL-SPREAD',
  'SUPPLY-006': 'ORG-SKILL-SPREAD',
  'SUPPLY-007': 'ORG-SKILL-SPREAD',
  'SUPPLY-008': 'ORG-SKILL-SPREAD',
  'DEP-001': 'ORG-SKILL-SPREAD',
  'DEP-002': 'ORG-SKILL-SPREAD',
  'DEP-003': 'ORG-SKILL-SPREAD',
  'DEP-004': 'ORG-SKILL-SPREAD',

  // Memory/context
  'MEM-001': 'MEM-POISON',
  'MEM-002': 'MEM-POISON',
  'MEM-003': 'MEM-POISON',
  'MEM-004': 'MEM-POISON',
  'MEM-005': 'MEM-POISON',

  // RAG poisoning
  'RAG-001': 'RAG-POISON',
  'RAG-002': 'RAG-POISON',
  'RAG-003': 'RAG-POISON',
  'RAG-004': 'RAG-POISON',

  // Identity spoofing
  'AIM-001': 'AGENT-IMPERSONATE',
  'AIM-002': 'AGENT-IMPERSONATE',
  'AIM-003': 'AGENT-IMPERSONATE',

  // Agent DNA forgery
  'DNA-001': 'BEHAVIORAL-IMPERSONATE',
  'DNA-002': 'BEHAVIORAL-IMPERSONATE',
  'DNA-003': 'BEHAVIORAL-IMPERSONATE',

  // Skill memory
  'SKILL-MEM-001': 'SKILL-MEM-AMP',

  // Adversarial skill / frontmatter injection
  'ASKILL-002': 'SKILL-FRONTMATTER',
  'SKILL-001': 'SKILL-FRONTMATTER',
  'SKILL-004': 'SKILL-FRONTMATTER',
  'SKILL-005': 'SKILL-FRONTMATTER',
  'SKILL-007': 'SKILL-FRONTMATTER',
  'SKILL-008': 'SKILL-FRONTMATTER',
  'SKILL-009': 'SKILL-FRONTMATTER',
  'SKILL-010': 'SKILL-FRONTMATTER',
  'SKILL-011': 'SKILL-FRONTMATTER',
  'SKILL-012': 'SKILL-FRONTMATTER',
  'SKILL-018': 'SKILL-FRONTMATTER',
  'SKILL-019': 'SKILL-FRONTMATTER',
  'HEARTBEAT-007': 'SKILL-FRONTMATTER',

  // Gateway/config
  'GATEWAY-001': 'GATEWAY-EXPLOIT',
  'GATEWAY-002': 'GATEWAY-EXPLOIT',
  'GATEWAY-003': 'GATEWAY-EXPLOIT',
  'GATEWAY-004': 'GATEWAY-EXPLOIT',
  'GATEWAY-005': 'GATEWAY-EXPLOIT',
  'GATEWAY-006': 'GATEWAY-EXPLOIT',
  'GATEWAY-007': 'GATEWAY-EXPLOIT',
  'GATEWAY-008': 'GATEWAY-EXPLOIT',

  // MCP exploitation
  'MCP-001': 'MCP-EXPLOIT',
  'MCP-002': 'MCP-EXPLOIT',
  'MCP-003': 'MCP-EXPLOIT',
  'MCP-004': 'MCP-EXPLOIT',
  'MCP-005': 'MCP-EXPLOIT',
  'MCP-006': 'MCP-EXPLOIT',
  'MCP-007': 'MCP-EXPLOIT',
  'MCP-008': 'MCP-EXPLOIT',
  'MCP-009': 'MCP-EXPLOIT',
  'MCP-010': 'MCP-EXPLOIT',

  // NemoClaw sandbox security
  'HMA-NMC-001': 'NEMO-CRED-LEAK',
  'HMA-NMC-002': 'NEMO-CRED-LEAK',
  'HMA-NMC-003': 'NEMO-CRED-LEAK',
  'HMA-NMC-004': 'NEMO-CRED-LEAK',
  'HMA-NMC-005': 'NEMO-CRED-LEAK',
  'HMA-NMC-006': 'NEMO-CRED-LEAK',
  'HMA-NMC-010': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-011': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-012': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-013': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-014': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-015': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-020': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-021': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-022': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-023': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-024': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-030': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-031': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-032': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-033': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-034': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-040': 'NEMO-OPENCLAW-INHERIT',
  'HMA-NMC-041': 'NEMO-OPENCLAW-INHERIT',
  'HMA-NMC-042': 'NEMO-OPENCLAW-INHERIT',
  'HMA-NMC-050': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-051': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-052': 'NEMO-NETWORK-EXPOSE',

  // AI infrastructure exposure (research gap coverage)
  'LLM-001': 'LLM-EXPOSE',
  'LLM-002': 'LLM-EXPOSE',
  'LLM-003': 'LLM-EXPOSE',
  'LLM-004': 'LLM-EXPOSE',
  'AITOOL-001': 'AITOOL-EXPOSE',
  'AITOOL-002': 'AITOOL-EXPOSE',
  'AITOOL-003': 'AITOOL-EXPOSE',
  'AITOOL-004': 'AITOOL-EXPOSE',
  'A2A-001': 'A2A-EXPOSE',
  'A2A-002': 'A2A-EXPOSE',
  'MCP-011': 'MCP-EXPLOIT',
  'WEBCRED-001': 'RETROACTIVE-PRIV',

  // Code injection, supply chain, operational security
  // CODEINJ-001 removed — deduplicated with NEMO-005
  'INSTALL-001': 'SUPPLY-CHAIN-INSTALL',
  'SHELL-EXFIL-001': 'CRED-EXFIL',
  'CLIPASS-001': 'RETROACTIVE-PRIV',
  'INTEGRITY-001': 'INTEGRITY-BYPASS',
  'TOCTOU-001': 'TOCTOU-RACE',
  // TMPPATH-001 removed — deduplicated with NEMO-006
  'DOCKERINJ-001': 'CODE-INJECTION',
  // ENVLEAK-001 removed — deduplicated with NEMO-007
  'SANDBOX-005': 'SANDBOX-ESCAPE',
  'WEBEXPOSE-001': 'RETROACTIVE-PRIV',
  'WEBEXPOSE-002': 'RETROACTIVE-PRIV',
  'WEBEXPOSE-003': 'RETROACTIVE-PRIV',
  'SOUL-OVERRIDE-001': 'SOUL-INJECT',
  'MEM-006': 'MEM-POISON',
  'AGENT-CRED-001': 'RETROACTIVE-PRIV',

  // NemoClaw novel threat checks (NEMO-00x series)
  'NEMO-001': 'NEMO-SUPPLY-CHAIN',
  'NEMO-002': 'NEMO-SUPPLY-CHAIN',
  'NEMO-003': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-004': 'NEMO-CRED-LEAK',
  'NEMO-005': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-006': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-007': 'NEMO-CRED-LEAK',
  'NEMO-008': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-009': 'NEMO-SUPPLY-CHAIN',
  'NEMO-010': 'NEMO-OPENCLAW-INHERIT',

  // Parser differential checks (Session 18)
  'PARSE-001': 'PARSER-DIFFERENTIAL',
  'PARSE-002': 'PARSER-DIFFERENTIAL',
  'PARSE-003': 'PARSER-DIFFERENTIAL',
  'PARSE-004': 'PARSER-DIFFERENTIAL',
  'PARSE-005': 'PARSER-DIFFERENTIAL',
  'PARSE-006': 'PARSER-DIFFERENTIAL',
  'PARSE-007': 'PARSER-DIFFERENTIAL',
  'PARSE-008': 'PARSER-DIFFERENTIAL',
  'PARSE-009': 'PARSER-DIFFERENTIAL',
  'PARSE-010': 'PARSER-DIFFERENTIAL',

  // Persistent agent state checks (Session 18)
  'PERSIST-001': 'PERSIST-STATE',
  'PERSIST-002': 'PERSIST-STATE',
  'PERSIST-003': 'PERSIST-STATE',
  'PERSIST-004': 'PERSIST-STATE',
  'PERSIST-005': 'PERSIST-STATE',
  'PERSIST-006': 'PERSIST-STATE',
  'PERSIST-007': 'PERSIST-STATE',
  'PERSIST-008': 'PERSIST-STATE',
  'PERSIST-009': 'PERSIST-STATE',
  'PERSIST-010': 'PERSIST-STATE',

  // Fake tool injection checks (Session 18)
  'FAKETOOL-001': 'FAKETOOL-INJECT',
  'FAKETOOL-002': 'FAKETOOL-INJECT',
  'FAKETOOL-003': 'FAKETOOL-INJECT',
  'FAKETOOL-004': 'FAKETOOL-INJECT',
  'FAKETOOL-005': 'FAKETOOL-INJECT',
  'FAKETOOL-006': 'FAKETOOL-INJECT',
  'FAKETOOL-007': 'FAKETOOL-INJECT',
  'FAKETOOL-008': 'FAKETOOL-INJECT',
  'FAKETOOL-009': 'FAKETOOL-INJECT',
  'FAKETOOL-010': 'FAKETOOL-INJECT',

  // Context lifecycle assembly checks (Session 20)
  'LIFECYCLE-001': 'ASSEMBLY-INJECT',
  'LIFECYCLE-002': 'ASSEMBLY-INJECT',
  'LIFECYCLE-003': 'ASSEMBLY-INJECT',
  'LIFECYCLE-004': 'ASSEMBLY-INJECT',
  'LIFECYCLE-005': 'ASSEMBLY-INJECT',
  'LIFECYCLE-006': 'ASSEMBLY-INJECT',
  'LIFECYCLE-007': 'ASSEMBLY-INJECT',
  'LIFECYCLE-008': 'ASSEMBLY-INJECT',
  'LIFECYCLE-009': 'ASSEMBLY-INJECT',
  'LIFECYCLE-010': 'ASSEMBLY-INJECT',

  // Skill governance and exfiltration (SKILL-020+)
  'SKILL-020': 'SKILL-FRONTMATTER',
  'SKILL-021': 'SKILL-EXFIL',
  'SKILL-022': 'SKILL-EXFIL',
  'SKILL-023': 'SKILL-FRONTMATTER',
  'SKILL-024': 'SKILL-EXFIL',

  // Authentication, session, and access control
  'AUTH-001': 'RETROACTIVE-PRIV',
  'AUTH-002': 'RETROACTIVE-PRIV',
  'AUTH-003': 'RETROACTIVE-PRIV',
  'AUTH-004': 'RETROACTIVE-PRIV',
  'SESSION-001': 'RETROACTIVE-PRIV',
  'SESSION-002': 'RETROACTIVE-PRIV',
  'SESSION-003': 'RETROACTIVE-PRIV',
  'SESSION-004': 'RETROACTIVE-PRIV',

  // Credential / secret protection (env vars, IDE configs, git history)
  'ENV-001': 'RETROACTIVE-PRIV',
  'ENV-002': 'RETROACTIVE-PRIV',
  'ENV-003': 'RETROACTIVE-PRIV',
  'ENV-004': 'RETROACTIVE-PRIV',
  'ENVLEAK-001': 'RETROACTIVE-PRIV',
  'ENCRYPT-001': 'RETROACTIVE-PRIV',
  'ENCRYPT-002': 'RETROACTIVE-PRIV',
  'ENCRYPT-003': 'RETROACTIVE-PRIV',
  'ENCRYPT-004': 'RETROACTIVE-PRIV',
  'GIT-001': 'RETROACTIVE-PRIV',
  'GIT-002': 'RETROACTIVE-PRIV',
  'GIT-003': 'RETROACTIVE-PRIV',
  'CURSOR-001': 'RETROACTIVE-PRIV',
  'VSCODE-001': 'RETROACTIVE-PRIV',
  'VSCODE-002': 'RETROACTIVE-PRIV',
  'API-KEY-EXPOSED': 'RETROACTIVE-PRIV',
  'CONFIG-EXPOSED': 'RETROACTIVE-PRIV',
  'CLAUDE-MD-EXPOSED': 'RETROACTIVE-PRIV',

  // Defense-in-depth: secrets management, encryption library, key rotation
  'SEC-001': 'RETROACTIVE-PRIV',
  'SEC-002': 'RETROACTIVE-PRIV',
  'SEC-003': 'RETROACTIVE-PRIV',
  'SEC-004': 'RETROACTIVE-PRIV',

  // CLAUDE.md governance (Claude Code agent config)
  'CLAUDE-001': 'RETROACTIVE-PRIV',
  'CLAUDE-002': 'SOUL-INJECT',
  'CLAUDE-003': 'SOUL-INJECT',
  'CLAUDE-004': 'SOUL-INJECT',
  'CLAUDE-005': 'MEM-POISON',
  'CLAUDE-006': 'SOUL-INJECT',
  'CLAUDE-007': 'SOUL-INJECT',

  // Agent-runtime configuration (CONFIG-* family — session files, daemons, sandbox, gateway)
  'CONFIG-001': 'RETROACTIVE-PRIV',
  'CONFIG-002': 'SOUL-INJECT',
  'CONFIG-003': 'NEMO-SANDBOX-ESCAPE',
  'CONFIG-004': 'RETROACTIVE-PRIV',
  'CONFIG-005': 'MEM-POISON',
  'CONFIG-006': 'SOUL-FORK',
  'CONFIG-007': 'SOUL-INJECT',
  'CONFIG-008': 'NEMO-SANDBOX-ESCAPE',
  'CONFIG-009': 'RETROACTIVE-PRIV',

  // Tool-boundary governance
  'TOOL-001': 'SOUL-INJECT',
  'TOOL-002': 'SOUL-INJECT',
  'TOOL-003': 'SOUL-INJECT',
  'TOOL-004': 'SOUL-INJECT',

  // Code injection / input validation defense gaps
  'CODEINJ-001': 'CODE-INJECTION',
  'INJ-001': 'CODE-INJECTION',
  'INJ-002': 'CODE-INJECTION',
  'INJ-003': 'CODE-INJECTION',
  'INJ-004': 'CODE-INJECTION',

  // Filesystem / process / sandbox / temp-path. IO-002 is "Query Parameterization"
  // (SQL-injection defense gap), distinct from the rest of the IO family.
  'IO-001': 'NEMO-SANDBOX-ESCAPE',
  'IO-002': 'CODE-INJECTION',
  'IO-003': 'NEMO-SANDBOX-ESCAPE',
  'IO-004': 'NEMO-SANDBOX-ESCAPE',
  'PERM-001': 'NEMO-SANDBOX-ESCAPE',
  'PERM-002': 'NEMO-SANDBOX-ESCAPE',
  'PERM-003': 'NEMO-SANDBOX-ESCAPE',
  'PROC-001': 'NEMO-SANDBOX-ESCAPE',
  'PROC-002': 'NEMO-SANDBOX-ESCAPE',
  'PROC-003': 'NEMO-SANDBOX-ESCAPE',
  'PROC-004': 'NEMO-SANDBOX-ESCAPE',
  'SANDBOX-001': 'SANDBOX-ESCAPE',
  'SANDBOX-002': 'SANDBOX-ESCAPE',
  'SANDBOX-003': 'SANDBOX-ESCAPE',
  'SANDBOX-004': 'SANDBOX-ESCAPE',
  'TMPPATH-001': 'SANDBOX-ESCAPE',

  // Network exposure / exfiltration channels
  'NET-004': 'SKILL-EXFIL',
  'NET-005': 'SKILL-EXFIL',
  'NET-006': 'SKILL-EXFIL',

  // API surface (gateway-class issues, headers, versioning, key-in-URL)
  'API-001': 'GATEWAY-EXPLOIT',
  'API-002': 'GATEWAY-EXPLOIT',
  'API-003': 'RETROACTIVE-PRIV',
  'API-004': 'GATEWAY-EXPLOIT',

  // External MCP scanner (port-level findings)
  'MCP-SSE': 'MCP-EXPLOIT',
  'MCP-TOOLS': 'MCP-EXPLOIT',

  // CVE / supply-chain advisories
  'CVE-001': 'ORG-SKILL-SPREAD',
  'CVE-002': 'ORG-SKILL-SPREAD',
  'CVE-003': 'ORG-SKILL-SPREAD',
  'CVE-004': 'ORG-SKILL-SPREAD',

  // Audit / logging integrity gaps
  'AUDIT-001': 'INTEGRITY-BYPASS',
  'AUDIT-002': 'INTEGRITY-BYPASS',
  'AUDIT-003': 'INTEGRITY-BYPASS',
  'AUDIT-004': 'INTEGRITY-BYPASS',
  'LOG-001': 'INTEGRITY-BYPASS',
  'LOG-002': 'INTEGRITY-BYPASS',
  'LOG-003': 'INTEGRITY-BYPASS',
  'LOG-004': 'INTEGRITY-BYPASS',
  'RATE-001': 'INTEGRITY-BYPASS',
  'RATE-002': 'INTEGRITY-BYPASS',
  'RATE-003': 'INTEGRITY-BYPASS',
  'RATE-004': 'INTEGRITY-BYPASS',

  // Semantic engine — Layer 2 structural analyzers (credential, instruction,
  // permission). SEM-MCP-* set `attackClass` inline at the emission site and
  // are not listed here. SemanticFinding uses `id:` (not `checkId:`); the
  // adapter at `src/semantic/integration/finding-adapter.ts` copies it into
  // `SecurityFinding.checkId` before `enrichWithTaxonomy` runs.
  'SEM-CRED-001': 'RETROACTIVE-PRIV',
  'SEM-CRED-002': 'RETROACTIVE-PRIV',
  'SEM-CRED-003': 'RETROACTIVE-PRIV',
  'SEM-CRED-004': 'RETROACTIVE-PRIV',
  'SEM-INST-001': 'SOUL-INJECT',
  'SEM-INST-002': 'SOUL-INJECT',
  'SEM-INST-003': 'SOUL-INJECT',
  'SEM-INST-004': 'SOUL-INJECT',
  'SEM-PERM-001': 'SOUL-INJECT',
  'SEM-PERM-002': 'SOUL-INJECT',
  'SEM-PERM-003': 'SANDBOX-ESCAPE',

  // AST capability-analyzer: AST-EXFIL-001 sets `attackClass: surface.attackClass`
  // dynamically at the emission site (capability-analyzer.ts:232). This entry
  // is a defensive fallback for the rare case where `surface.attackClass` is
  // undefined; the inline assignment takes precedence per
  // `enrichWithTaxonomy`'s precedence rule.
  'AST-EXFIL-001': 'SKILL-EXFIL',

  // AST scope-analyzer: AST-SCOPE-004 sets `attackClass: family.attackClass`
  // dynamically at the emission site (scope-analyzer.ts), varying by directive
  // family (PRIV-ESCALATION / PERSIST / CRED-HARVEST). This entry is the
  // defensive fallback; the inline assignment takes precedence.
  'AST-SCOPE-004': 'PRIV-ESCALATION',

  // The rest of the NanoMind semantic (AST) layer, same shape as
  // AST-EXFIL-001 / AST-SCOPE-004 above (HMA-29): every one of these is
  // emitted with `attackClass:` set inline at the emission site, and the
  // inline assignment takes precedence per `enrichWithTaxonomy`. The
  // entries are the defensive fallback AND the inventory membership —
  // before them `secure` could report AST-CRED-001 while `check-metadata`
  // (totalChecks, the checks table) denied it exists. Sites that vary the
  // class by matched pattern (AST-CRED-001, AST-GOV-003, AST-PROMPT-001,
  // AST-PROMPT-004, AST-SCOPE-001) list their primary class here.
  'AST-CAP-001': 'PRIV-ESCALATION',
  'AST-CAP-002': 'CAPABILITY-ABUSE',
  'AST-CODE-001': 'CMD-INJECT',
  'AST-CODE-002': 'UNSAFE-DESER',
  'AST-CODE-003': 'PATH-TRAVERSAL',
  'AST-CRED-001': 'CRED-EXPOSURE',
  'AST-CRED-002': 'CRED-EXFIL',
  'AST-CRED-003': 'CRED-HARDCODED',
  'AST-GOV-001': 'SOUL-GAP',
  'AST-GOV-002': 'SOUL-BYPASS',
  'AST-GOV-003': 'SOUL-MISSING',
  'AST-GOV-004': 'PROMPT-INJECT',
  'AST-GOV-005': 'SOUL-GAP',
  'AST-HEARTBEAT-001': 'HEARTBEAT-RCE',
  'AST-INJECT-001': 'PROMPT-INJECT',
  'AST-MANIP-001': 'SCAN-EVASION',
  'AST-PERSIST-001': 'PERSISTENCE',
  'AST-PROMPT-001': 'JAILBREAK',
  'AST-PROMPT-002': 'CAPABILITY-CREEP',
  'AST-PROMPT-003': 'PROMPT-INJECT',
  'AST-PROMPT-004': 'AUTHORITY-CONFUSION',
  'AST-SCOPE-001': 'SCOPE-WILDCARD',
  'AST-SCOPE-002': 'SCOPE-UNDECLARED',
  'AST-SCOPE-003': 'SEMANTIC-MISMATCH',

  // SOUL narrative-analysis checks (the scanner's soul-analysis
  // integration, src/hardening/scanner.ts), same HMA-29 shape: each is
  // emitted with an inline attackClass equal to the class here.
  'SOUL-BYPASS': 'SOUL-BYPASS',
  'SOUL-COMPLETENESS': 'SOUL-COMPLETENESS',
  'SOUL-CONSENT': 'SOUL-CONSENT',
  'SOUL-CONTRADICTION': 'SOUL-CONTRADICTION',
  'SOUL-ESCAPE-CLAUSE': 'SOUL-ESCAPE-CLAUSE',
  'SOUL-UNVERIFIABLE-CLAIM': 'SOUL-UNVERIFIABLE-CLAIM',
};

/**
 * CheckIds intentionally excluded from `attackClass` enforcement. These are
 * operational / meta findings emitted by the scanner that report status
 * (oversized file, fix-application result, scan target unreachable in some
 * paths) rather than a security threat. They should not carry an attack
 * class because they are not threats themselves. The deterministic
 * coverage test (`__tests__/hardening/taxonomy-coverage.test.ts`) skips
 * these IDs.
 */
export const TAXONOMY_EXEMPT_CHECKIDS: ReadonlySet<string> = new Set([
  // #462 — reports that Layer 3 sent a file for analysis and got back a result
  // it could not read, so that file is NOT examined for the credential shapes
  // only Layer 3 detects. A coverage statement about this run, in the same
  // family as FIX-WRITE-FAILED below: it names an absence of measurement, not a
  // threat, and any threat in the file is still reported by whichever other
  // layer found it, carrying that layer's attack class.
  'SEM-LLM-NOT-ANALYZED',
  'FIX-ERROR',
  // Reports that `--fix` was skipped because no backup could be taken, so the
  // run detected only. A fix-application status, not a threat.
  'FIX-BACKUP-FAILED',
  // Reports that a computed fix could not be written to disk (read-only
  // mount, immutable flag, EPERM, full volume). A fix-application status,
  // like FIX-ERROR beside it — the underlying threat is still reported by
  // whichever check found it, which carries its own attack class.
  'FIX-WRITE-FAILED',
  'FIX-SUMMARY',
  'SCAN-001',
  // External port-scanner status — `Score is not applicable — nothing was tested`.
  // A scan-status indicator, not a security threat.
  'SCAN-UNREACHABLE',
  // Reports that a fix landed inside a nested project's backup directory, so
  // that project's own `rollback` no longer restores the original. A statement
  // about what THIS run did and how to undo it, in the same family as
  // FIX-WRITE-FAILED beside it — the credential it redacted is reported by
  // CRED-001, which carries its own attack class.
  'FIX-FOREIGN-ARCHIVE',
  // #438 — reports that a file inside the target was discovered and could not
  // be read, so no check examined it. The same family as SEM-LLM-NOT-ANALYZED
  // above: it names an ABSENCE of measurement rather than a threat. Giving it
  // an attack class would assert something about the file's contents, which is
  // precisely what this run could not determine — the finding exists to say
  // that nothing is known about it.
  'SCAN-UNREAD-001',
  // Reports that a payload was still encoded when the decoder's depth bound
  // stopped it, so the plaintext below that point was examined by nothing. The
  // same family as SCAN-UNREAD-001 and SEM-LLM-NOT-ANALYZED above: it names an
  // ABSENCE of measurement. An attack class here would be a claim about what
  // the undecoded bytes contain, which is the one thing the run could not
  // determine — the layers it DID decode are reported by whichever rules
  // matched them, each carrying its own class.
  'SCAN-DECODE-BOUND',
]);

/**
 * A check-id family (or exact ids within one) deliberately outside the
 * TAXONOMY_MAP inventory, with the reason stated — the exemption mechanism
 * above, made visible (HMA-29). `check-metadata --json` publishes these so
 * "totalChecks" plus the exclusions is the whole story of what `secure`
 * can emit, and the census test
 * (`__tests__/hardening/checkid-census.test.ts`) holds emitted ids to
 * exactly this contract: inventory key, or declared here.
 */
export interface CheckIdExclusion {
  /** Family prefix (the segment before the first hyphen), e.g. 'FIX'. */
  family: string;
  /** Exact excluded ids. Empty means the entire family is excluded. */
  ids: string[];
  /** Why these ids carry no inventory entry. */
  reason: string;
}

/**
 * Reasons for the exempt families above. A future exempt id in a new
 * family falls back to the generic operational/meta wording rather than
 * shipping reasonless.
 */
const EXEMPT_FAMILY_REASONS: Record<string, string> = {
  FIX: 'Fix-application statuses: they report what a --fix run did (or could not do), not a security threat. The underlying threat is reported by whichever check found it, which carries its own inventory entry.',
  SCAN: 'Scan-status indicators: they report that something was not examined or not reachable — an absence of measurement, not a threat in the target.',
  SEM: 'Layer-3 coverage statement: SEM-LLM-NOT-ANALYZED names a file the semantic layer could not analyze. An inventory entry would assert something about contents the run could not determine.',
};
const GENERIC_EXEMPT_REASON =
  'Operational/meta finding: reports scanner status rather than a security threat, so it carries no inventory entry.';

/**
 * Whole families excluded from the inventory. CHK-* ids exist only as
 * fixtures inside the eval oracle’s own in-src test suite
 * (src/eval/__tests__/oracle.test.ts); no scanner path emits them, but the
 * emitted-literal census reads them, so the exclusion is declared rather
 * than left to the census’s file-selection heuristics.
 */
const FAMILY_EXCLUSIONS: readonly CheckIdExclusion[] = [
  {
    family: 'CHK',
    ids: [],
    reason: 'Test fixtures of the eval oracle’s in-src suite (src/eval/__tests__/oracle.test.ts). Never emitted by a scan; excluded as a family so new fixture ids need no bookkeeping.',
  },
];

/**
 * Every deliberate hole in the inventory, stated with its reason:
 * TAXONOMY_EXEMPT_CHECKIDS grouped by family, plus the whole-family
 * exclusions. This is what `check-metadata --json` publishes.
 */
export function getDeclaredCheckIdExclusions(): CheckIdExclusion[] {
  const byFamily = new Map<string, string[]>();
  for (const id of [...TAXONOMY_EXEMPT_CHECKIDS].sort()) {
    const family = id.split('-')[0];
    const ids = byFamily.get(family);
    if (ids) ids.push(id);
    else byFamily.set(family, [id]);
  }
  const declared: CheckIdExclusion[] = [...byFamily.entries()].map(([family, ids]) => ({
    family,
    ids,
    reason: EXEMPT_FAMILY_REASONS[family] ?? GENERIC_EXEMPT_REASON,
  }));
  declared.push(...FAMILY_EXCLUSIONS.map((e) => ({ ...e, ids: [...e.ids] })));
  declared.sort((a, b) => (a.family < b.family ? -1 : a.family > b.family ? 1 : 0));
  return declared;
}

/** True when `checkId` is deliberately outside the inventory, with a declared reason. */
export function isDeclaredExcludedCheckId(checkId: string): boolean {
  if (TAXONOMY_EXEMPT_CHECKIDS.has(checkId)) return true;
  const family = checkId.split('-')[0];
  return FAMILY_EXCLUSIONS.some((e) => e.ids.length === 0 && e.family === family);
}

/**
 * Default severity by check ID prefix. Based on the security impact
 * of each category. Individual checks may override via SEVERITY_OVERRIDES.
 */
const PREFIX_SEVERITY: Record<string, string> = {
  CRED: 'critical',
  WEBCRED: 'critical',
  LLM: 'critical',
  AITOOL: 'critical',
  DEP: 'critical',
  GATEWAY: 'critical',
  HEARTBEAT: 'critical',
  FAKETOOL: 'critical',
  DOCKERINJ: 'critical',
  TOCTOU: 'critical',
  SANDBOX: 'critical',
  INSTALL: 'critical',
  INTEGRITY: 'critical',
  CLIPASS: 'critical',
  PERSIST: 'high',
  MEM: 'high',
  SOUL: 'high',
  SKILL: 'high',
  MCP: 'high',
  PROMPT: 'high',
  SUPPLY: 'high',
  LIFECYCLE: 'high',
  A2A: 'high',
  AIM: 'high',
  NET: 'high',
  GIT: 'high',
  AGENT: 'high',
  RAG: 'high',
  ASKILL: 'high',
  HMA: 'medium',
  NEMO: 'medium',
  PARSE: 'medium',
  UNICODE: 'medium',
  DNA: 'medium',
  WEBEXPOSE: 'medium',
};

/** Per-check severity overrides where the default prefix doesn't apply. */
const SEVERITY_OVERRIDES: Record<string, string> = {
  'HEARTBEAT-006': 'medium',
  'SKILL-005': 'medium',
  'SKILL-018': 'medium',
  'SUPPLY-002': 'medium',
  'SEM-MCP-006': 'low',
};

/**
 * Look up the default severity for a check ID.
 * Returns 'medium' if no mapping exists.
 */
export function getCheckSeverity(checkId: string): string {
  if (SEVERITY_OVERRIDES[checkId]) return SEVERITY_OVERRIDES[checkId];
  // Try progressively shorter prefixes: SEM-CRED -> SEM, SOUL-TH -> SOUL
  const parts = checkId.replace(/-\d+$/, '').split('-');
  for (let i = parts.length; i > 0; i--) {
    const prefix = parts.slice(0, i).join('-');
    if (PREFIX_SEVERITY[prefix]) return PREFIX_SEVERITY[prefix];
  }
  return 'medium';
}

/**
 * Look up the attack class for a given HMA check ID.
 * Returns undefined if no mapping exists.
 */
export function getAttackClass(checkId: string): string | undefined {
  return TAXONOMY_MAP[checkId];
}

/** Return a copy of the full taxonomy map (checkId -> attackClass). */
export function getTaxonomyMap(): Record<string, string> {
  return { ...TAXONOMY_MAP };
}

/**
 * Check-ID prefixes for the NanoMind semantic (AST) layer. Everything else in
 * the taxonomy is a static rule check.
 */
const SEMANTIC_CHECK_PREFIXES = ['SEM-', 'AST-'] as const;

function isSemanticCheckId(checkId: string): boolean {
  return SEMANTIC_CHECK_PREFIXES.some(p => checkId.startsWith(p));
}

/** Category slug for a check ID: everything before the trailing "-NNN" index. */
function categoryOf(checkId: string): string {
  const parts = checkId.split('-');
  return (parts.length > 1 ? parts.slice(0, -1).join('-') : parts[0]).toLowerCase();
}

export interface CheckCounts {
  /** Total distinct checks (static + semantic). */
  total: number;
  /** Static rule checks (non SEM-/AST-). */
  static: number;
  /** NanoMind semantic (AST) checks present in the taxonomy. */
  semantic: number;
  /** Distinct categories across all checks. */
  totalCategories: number;
  /** Distinct categories across static checks only. */
  staticCategories: number;
}

/**
 * The single source of truth for every user-facing check/category count.
 * Derived from TAXONOMY_MAP so `--help`, command descriptions, the scan
 * Observations block, `check-metadata`, README and docs cannot drift apart.
 * Before this existed the scan display hardcoded "209 static / 44 categories"
 * while --help derived 323/74 from the same map — a self-contradiction a user
 * running the CLI could see. Keep the golden values in
 * `__tests__/hardening/check-count-consistency.test.ts` updated when the
 * taxonomy changes; that test fails on drift by design.
 */
export function getCheckCounts(): CheckCounts {
  const ids = Object.keys(TAXONOMY_MAP);
  const staticIds = ids.filter(id => !isSemanticCheckId(id));
  const semanticIds = ids.filter(isSemanticCheckId);
  return {
    total: ids.length,
    static: staticIds.length,
    semantic: semanticIds.length,
    totalCategories: new Set(ids.map(categoryOf)).size,
    staticCategories: new Set(staticIds.map(categoryOf)).size,
  };
}

/**
 * Enrich an array of SecurityFindings with their attack class mappings.
 * Modifies findings in place. Findings that already carry an `attackClass`
 * (set inline at the emission site, e.g. `AST-CRED-001` →
 * `CRED-EXPOSURE`) are left untouched — inline values take precedence
 * over the table lookup.
 */
export function enrichWithTaxonomy(findings: SecurityFindingDraft[]): void {
  for (const finding of findings) {
    if (finding.attackClass) continue;
    const attackClass = getAttackClass(finding.checkId);
    if (attackClass) {
      finding.attackClass = attackClass;
    }
  }
}
