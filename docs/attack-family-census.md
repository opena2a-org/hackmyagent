# Attack family census

Measured 2026-10-10.

HackMyAgent tags every check with an attack **family**, such as `MCP-EXPLOIT`
or `SOUL-INJECT`. A family names the surface a check inspects. It is not an
attack **class**. The ten canonical attack classes name what the attacker is
after: `injection`, `exfiltration`, `credential_abuse`,
`privilege_escalation`, `persistence`, `lateral_movement`,
`social_engineering`, `policy_violation`, `steganography` and `benign`.

Three registers hold family codes. This census lists every code in any of
them, the one class it belongs to, and what happens to it where the registers
disagree.

| Register | What was read | Commit measured | Family codes |
|---|---|---|---|
| HackMyAgent taxonomy | `TAXONOMY_MAP` in `src/hardening/taxonomy.ts`, 362 check ids | hackmyagent `078c7617` | 75 |
| Agent threat matrix | `attackClasses[].id` in `matrix.json`, 61 techniques | agent-threat-matrix `5ab8e70` | 40 |
| OpenA2A Registry | every identifier seeded into the `attack_classes` table | opena2a-registry `9da08495` | 42 |

77 codes appear in at least one register, and 35 appear in all three.

The class of each family is code, not only this table: `FAMILY_CLASS` in
`src/hardening/taxonomy.ts`, read through `getCanonicalClass`, which throws on
a code it does not know rather than passing it through. `hackmyagent
check-metadata --json` reports both keys for every check: `attackClass` holds
the family and `canonicalClass` holds the class.

## How a family gets its class

- The class is the attacker's objective, not the carrier the attack arrives
  in.
- Where a family's description names two objectives, the family's name
  decides.
- Evasion and artifact-channel families (`UNICODE-STEGO`,
  `PARSER-DIFFERENTIAL`, `TOCTOU-RACE`, `SCAN-EVASION`) take the objective of
  the payload they carry, `injection`.
- `JAILBREAK` is `policy_violation`: the principal's own prompt defeating the
  model's policy. `injection` is a third party's instruction arriving as data.
- `steganography` is reserved for hidden data as the objective, and no family
  detects that today. A finding family is never `benign`. Both classes hold no
  family.

| Class | Families |
|---|---|
| `injection` | 20 |
| `exfiltration` | 4 |
| `credential_abuse` | 6 |
| `privilege_escalation` | 18 |
| `persistence` | 3 |
| `lateral_movement` | 1 |
| `social_engineering` | 1 |
| `policy_violation` | 16 |
| `steganography` | 0 |
| `benign` | 0 |

69 families in all: the 77 codes less the four fold codes and the four
`SOUL-HV-00N` spellings below.

## Census

- **taxonomy.ts check ids**: the `TAXONOMY_MAP` keys that map to the code at
  the measured commit. `PREFIX-001..004` is a run of consecutive ids.
- **Matrix techniques**: the family's own `techniques` list. `absent` means
  the matrix has no family with that id.
- **Registry**: `seeded` when a migration or the taxonomy seed script inserts
  the identifier.
- **Disposition**: `keep`; `fold into X`, for a code naming a condition that
  family X already holds; `merge into X`, for a check-id spelling of family
  X; and the registers a kept family is to be added to.

| Code | Canonical class | taxonomy.ts check ids | Matrix techniques | Registry | Disposition |
|---|---|---|---|---|---|
| `ASSEMBLY-INJECT` | `injection` | LIFECYCLE-001..010 | T-7007 | absent | keep; add to Registry |
| `AUTHORITY-CONFUSION` | `injection` | AST-PROMPT-004, TEXT-002 | absent | absent | keep; add to matrix and Registry |
| `CMD-INJECT` | `injection` | AST-CODE-001 | absent | absent | fold into CODE-INJECTION |
| `CODE-INJECTION` | `injection` | DOCKERINJ-001, INJ-001..004, IO-002 | T-7002, T-9001 | seeded | keep |
| `FAKETOOL-INJECT` | `injection` | FAKETOOL-001..010 | T-4007 | absent | keep; add to Registry |
| `HEARTBEAT-RCE` | `injection` | AST-HEARTBEAT-001, HEARTBEAT-001..006, SKILL-002, SKILL-003 | T-6005, T-9003 | seeded | keep |
| `INTEGRITY-BYPASS` | `injection` | AUDIT-001..004, INTEGRITY-001, LOG-001..004, RATE-001..004 | T-9001 | seeded | keep |
| `MCP-SUPPLY-CHAIN` | `injection` | SEM-MCP-008 | absent | absent | keep; add to matrix and Registry |
| `MCP-TYPOSQUAT` | `injection` | SEM-MCP-007 | absent | absent | keep; add to matrix and Registry |
| `NEMO-SUPPLY-CHAIN` | `injection` | HMA-NMC-020..024, NEMO-001, NEMO-002, NEMO-009 | T-9006 | seeded | keep |
| `PARSER-DIFFERENTIAL` | `injection` | PARSE-001..010 | T-2009 | absent | keep; add to Registry |
| `PROMPT-INJECT` | `injection` | AST-GOV-004, AST-INJECT-001, AST-PROMPT-003 | absent | absent | fold into SOUL-INJECT |
| `RAG-POISON` | `injection` | RAG-001..004 | T-2002, T-7006 | seeded | keep |
| `SCAN-EVASION` | `injection` | AST-MANIP-001 | absent | absent | keep; add to matrix and Registry |
| `SKILL-FRONTMATTER` | `injection` | ASKILL-002, HEARTBEAT-007, SKILL-001, SKILL-004, SKILL-005, SKILL-007..012, SKILL-018..020, SKILL-023 | T-2005, T-6004, T-6006 | seeded | keep |
| `SOUL-HIJACK` | `injection` | SOUL-HO-001, SOUL-HO-002 | T-4002, T-5002 | seeded | keep |
| `SOUL-INJECT` | `injection` | CLAUDE-002..004, CLAUDE-006, CLAUDE-007, CONFIG-002, CONFIG-007, PROMPT-001..004, SEM-INST-001..004, SEM-PERM-001, SEM-PERM-002, SOUL-IH-001, SOUL-IH-002, SOUL-OVERRIDE-001, TEXT-001, TOOL-001..004 | T-1003, T-2001, T-2003, T-2007, T-2008 | seeded | keep |
| `SOUL-POISON` | `injection` | SOUL-TH-001, SOUL-TH-002 | T-2001, T-2003, T-2007, T-2008 | seeded | keep |
| `SUPPLY-CHAIN-INSTALL` | `injection` | INSTALL-001 | T-9003 | seeded | keep |
| `TOCTOU-RACE` | `injection` | TOCTOU-001 | T-9001 | seeded | keep |
| `UNICODE-STEGO` | `injection` | UNICODE-STEGO-001..005 | T-2006, T-4005 | seeded | keep |
| `UNSAFE-DESER` | `injection` | AST-CODE-002 | absent | absent | keep; add to matrix and Registry |
| `GATEWAY-EXPLOIT` | `exfiltration` | API-001, API-002, API-004, GATEWAY-001..008 | T-6003 | seeded | keep |
| `MCP-CHAIN-EXFIL` | `exfiltration` | SEM-MCP-005 | absent | absent | keep; add to matrix and Registry |
| `PATH-TRAVERSAL` | `exfiltration` | AST-CODE-003 | absent | absent | keep; add to matrix and Registry |
| `SKILL-EXFIL` | `exfiltration` | AST-EXFIL-001, NET-001..006, SKILL-006, SKILL-021, SKILL-022, SKILL-024 | T-5001, T-7003, T-8001, T-8002, T-8003, T-8004, T-8006 | seeded | keep |
| `BEHAVIORAL-IMPERSONATE` | `credential_abuse` | DNA-001..003 | T-4002 | seeded | keep |
| `CRED-EXFIL` | `credential_abuse` | AST-CRED-002, SHELL-EXFIL-001 | absent | seeded | keep; add to matrix |
| `CRED-EXPOSURE` | `credential_abuse` | AST-CRED-001 | absent | absent | keep; add to matrix and Registry |
| `CRED-HARDCODED` | `credential_abuse` | AST-CRED-003 | absent | absent | keep; add to matrix and Registry |
| `MCP-CRED` | `credential_abuse` | SEM-MCP-003 | absent | absent | keep; add to matrix and Registry |
| `NEMO-CRED-LEAK` | `credential_abuse` | HMA-NMC-001..006, NEMO-004, NEMO-007 | T-3002, T-7005 | seeded | keep |
| `A2A-EXPOSE` | `privilege_escalation` | A2A-001, A2A-002 | T-1006, T-5002 | seeded | keep |
| `AITOOL-EXPOSE` | `privilege_escalation` | AITOOL-001..004 | T-1001, T-1004, T-1005 | seeded | keep |
| `CAPABILITY-ABUSE` | `privilege_escalation` | AST-CAP-002 | absent | absent | keep; add to matrix and Registry |
| `CAPABILITY-CREEP` | `privilege_escalation` | AST-PROMPT-002 | absent | absent | keep; add to matrix and Registry |
| `LLM-EXPOSE` | `privilege_escalation` | LLM-001..004 | T-1001, T-1004 | seeded | keep |
| `MCP-EXPLOIT` | `privilege_escalation` | MCP-001..011, MCP-SSE, MCP-TOOLS | T-1002, T-1005, T-4003, T-5003, T-5005, T-5006 | seeded | keep |
| `MCP-PRIV-ESC` | `privilege_escalation` | SEM-MCP-001, SEM-MCP-002 | absent | absent | fold into MCP-EXPLOIT |
| `MCP-SCOPE-EXPAND` | `privilege_escalation` | SEM-MCP-006 | absent | absent | keep; add to matrix and Registry |
| `MCP-SCOPE-WILDCARD` | `privilege_escalation` | SEM-MCP-004 | absent | absent | keep; add to matrix and Registry |
| `NEMO-NETWORK-EXPOSE` | `privilege_escalation` | HMA-NMC-010..015, HMA-NMC-050..052 | T-1001, T-1004, T-5001 | seeded | keep |
| `NEMO-OPENCLAW-INHERIT` | `privilege_escalation` | HMA-NMC-040..042, NEMO-010 | T-1001 | seeded | keep |
| `NEMO-SANDBOX-ESCAPE` | `privilege_escalation` | CONFIG-003, CONFIG-008, HMA-NMC-030..034, IO-001, IO-003, IO-004, NEMO-003, NEMO-005, NEMO-006, NEMO-008, PERM-001..003, PROC-001..004 | T-7001 | seeded | keep |
| `PRIV-DRIFT` | `privilege_escalation` | absent | absent | seeded | keep; add to matrix with no check (no detector) |
| `PRIV-ESCALATION` | `privilege_escalation` | AST-CAP-001, AST-SCOPE-004 | absent | seeded | keep; add to matrix |
| `RETROACTIVE-PRIV` | `privilege_escalation` | AGENT-CRED-001, API-003, AUTH-001..004, CLAUDE-001, CLIPASS-001, CONFIG-001, CONFIG-004, CONFIG-009, CRED-001..004, CURSOR-001, ENCRYPT-001..004, ENV-001..004, GIT-001..003, SEC-001..004, SEM-CRED-001..004, SESSION-001..004, SKILL-025, VSCODE-001, VSCODE-002, WEBCRED-001, WEBEXPOSE-001..003, API-KEY-EXPOSED, CLAUDE-MD-EXPOSED, CONFIG-EXPOSED | T-1001, T-1004, T-1007, T-3001, T-3003, T-3005, T-3006, T-5004, T-8005 | seeded | keep |
| `SANDBOX-ESCAPE` | `privilege_escalation` | SANDBOX-001..005, SEM-PERM-003 | T-7001 | seeded | keep |
| `SCOPE-UNDECLARED` | `privilege_escalation` | AST-SCOPE-002 | absent | absent | keep; add to matrix and Registry |
| `SCOPE-WILDCARD` | `privilege_escalation` | AST-SCOPE-001 | absent | absent | keep; add to matrix and Registry |
| `SOUL-DELEGATE` | `privilege_escalation` | SOUL-DH-001, SOUL-DH-002 | T-4001 | seeded | keep |
| `MEM-POISON` | `persistence` | CLAUDE-005, CONFIG-005, MEM-001..006 | T-2002, T-3004, T-6001, T-6002, T-7004 | seeded | keep |
| `PERSIST-STATE` | `persistence` | PERSIST-001..010 | T-6007 | absent | keep; add to Registry |
| `PERSISTENCE` | `persistence` | AST-PERSIST-001 | absent | absent | fold into PERSIST-STATE |
| `SKILL-MEM-AMP` | `persistence` | SKILL-MEM-001 | T-3004 | seeded | keep |
| `ORG-SKILL-SPREAD` | `lateral_movement` | CVE-001..004, DEP-001..004, SUPPLY-001..008 | T-9002, T-9004, T-9005, T-9006 | seeded | keep |
| `AGENT-IMPERSONATE` | `social_engineering` | AIM-001..003 | T-4002, T-4004 | seeded | keep |
| `JAILBREAK` | `policy_violation` | AST-PROMPT-001 | absent | absent | keep; add to matrix and Registry |
| `PHANTOM-SOUL` | `policy_violation` | SOUL-HB-001, SOUL-HB-002 | T-1006 | seeded | keep |
| `SEMANTIC-MISMATCH` | `policy_violation` | AST-SCOPE-003 | absent | absent | keep; add to matrix and Registry |
| `SOUL-BOUNDARY` | `policy_violation` | SOUL-CB-001, SOUL-CB-002 | T-2008 | seeded | keep |
| `SOUL-BYPASS` | `policy_violation` | AST-GOV-002, SOUL-BYPASS | absent | absent | keep; add to matrix and Registry |
| `SOUL-COMPLETENESS` | `policy_violation` | SOUL-COMPLETENESS | absent | absent | keep; add to matrix and Registry |
| `SOUL-CONSENT` | `policy_violation` | SOUL-CONSENT | absent | absent | keep; add to matrix and Registry |
| `SOUL-CONTRADICTION` | `policy_violation` | SOUL-CONTRADICTION | absent | absent | keep; add to matrix and Registry |
| `SOUL-DRIFT` | `policy_violation` | SOUL-TH-003, SOUL-TH-004 | T-2004, T-4006 | seeded | keep |
| `SOUL-ESCAPE-CLAUSE` | `policy_violation` | SOUL-ESCAPE-CLAUSE | absent | absent | keep; add to matrix and Registry |
| `SOUL-FORK` | `policy_violation` | CONFIG-006, SOUL-AS-001, SOUL-AS-002, SOUL-HT-001, SOUL-HT-002 | T-5002 | seeded | keep |
| `SOUL-GAP` | `policy_violation` | AST-GOV-001, AST-GOV-005 | absent | absent | keep; add to matrix and Registry |
| `SOUL-HV` | `policy_violation` | absent | T-2001, T-2003 | absent | keep; takes SOUL-HV-001..004; Registry rows SOUL-HV-001..004 merge into it |
| `SOUL-HV-001` | `policy_violation` | SOUL-HV-001 | absent | seeded | merge into SOUL-HV |
| `SOUL-HV-002` | `policy_violation` | SOUL-HV-002 | absent | seeded | merge into SOUL-HV |
| `SOUL-HV-003` | `policy_violation` | SOUL-HV-003 | absent | seeded | merge into SOUL-HV |
| `SOUL-HV-004` | `policy_violation` | SOUL-HV-004 | absent | seeded | merge into SOUL-HV |
| `SOUL-IMPERSONATE` | `policy_violation` | SOUL-TH-005 | T-4002 | seeded | keep |
| `SOUL-MISSING` | `policy_violation` | AST-GOV-003 | absent | absent | keep; add to matrix and Registry |
| `SOUL-UNVERIFIABLE-CLAIM` | `policy_violation` | SOUL-UNVERIFIABLE-CLAIM | absent | absent | keep; add to matrix and Registry |

## Disagreements by id

### One condition, two codes

Four codes name a condition that another family already holds. Each folds
into that family and takes its class.

| Code | Checks | Folds into | The condition |
|---|---|---|---|
| `MCP-PRIV-ESC` | SEM-MCP-001, SEM-MCP-002 | `MCP-EXPLOIT` | SEM-MCP-001 reports what MCP-001 reports: a filesystem MCP server with unscoped reach |
| `CMD-INJECT` | AST-CODE-001 | `CODE-INJECTION` | command injection and shell execution in code |
| `PROMPT-INJECT` | AST-GOV-004, AST-INJECT-001, AST-PROMPT-003 | `SOUL-INJECT` | prompt injection and missing resistance to it, where PROMPT-001..004 already sit |
| `PERSISTENCE` | AST-PERSIST-001 | `PERSIST-STATE` | writes to persistent state |

`getCanonicalClass` already resolves each fold code through `FAMILY_FOLDS` to
its target's class. `TAXONOMY_MAP` still maps the seven checks to the fold
codes, because the analyzers that emit them still set those codes on the
finding.

### One family, five spellings

The matrix holds one harm-avoidance family, `SOUL-HV`. The taxonomy and the
Registry held four, one per control: `SOUL-HV-001` to `SOUL-HV-004`.
`TAXONOMY_MAP` now maps all four controls to `SOUL-HV`. The Registry's four
rows are to merge into one `SOUL-HV` row.

### Codes missing from a register

No family is dropped. A family missing from a register is added to it.

- In the taxonomy only, 26 after the folds, to add to the matrix and to the
  Registry: `AUTHORITY-CONFUSION`, `CAPABILITY-ABUSE`, `CAPABILITY-CREEP`,
  `CRED-EXPOSURE`, `CRED-HARDCODED`, `JAILBREAK`, `MCP-CHAIN-EXFIL`,
  `MCP-CRED`, `MCP-SCOPE-EXPAND`, `MCP-SCOPE-WILDCARD`, `MCP-SUPPLY-CHAIN`,
  `MCP-TYPOSQUAT`, `PATH-TRAVERSAL`, `SCAN-EVASION`, `SCOPE-UNDECLARED`,
  `SCOPE-WILDCARD`, `SEMANTIC-MISMATCH`, `SOUL-BYPASS`, `SOUL-COMPLETENESS`,
  `SOUL-CONSENT`, `SOUL-CONTRADICTION`, `SOUL-ESCAPE-CLAUSE`, `SOUL-GAP`,
  `SOUL-MISSING`, `SOUL-UNVERIFIABLE-CLAIM`, `UNSAFE-DESER`. The matrix lists
  none of their check ids under any family. Each goes into the matrix with its
  check ids and an empty technique list until a technique is observed.
- In the taxonomy and the matrix, not the Registry, 4 to add to the Registry:
  `ASSEMBLY-INJECT`, `FAKETOOL-INJECT`, `PARSER-DIFFERENTIAL`,
  `PERSIST-STATE`.
- In the taxonomy and the Registry, not the matrix, 2 to add to the matrix:
  `CRED-EXFIL`, `PRIV-ESCALATION`.
- In the Registry only: `PRIV-DRIFT`. It stays, and goes into the matrix with
  an empty check list: no HackMyAgent check detects it.

### Family strings set inline outside every register

Some source files set a family string inline, on a finding, a risk surface or
a simulation probe, instead of reading it from `TAXONOMY_MAP`. These 19
strings are in none of the three registers, so they have no class, and
`getCanonicalClass` refuses each of them. Their classes are not assigned
here.

| String | Set in |
|---|---|
| `ASSEMBLY-CONFLICT` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-DELIMITER` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-DILUTE` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-DISPLACE` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-HIDDEN` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-HIJACK` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-NOSAFETY` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-OVERFLOW` | `src/lifecycle/assembly-scanner.ts` |
| `ASSEMBLY-SPLIT` | `src/lifecycle/assembly-scanner.ts` |
| `AUTH-BYPASS` | `src/hardening/nemoclaw-scanner.ts` |
| `CRED-HARVEST` | `src/hardening/nemoclaw-scanner.ts`, `src/nanomind-core/analyzers/capability-analyzer.ts`, `src/nanomind-core/analyzers/scope-analyzer.ts`, `src/nanomind-core/compiler/semantic-compiler.ts`, `src/simulation/probes.ts` |
| `CRED-PERSIST` | `src/simulation/probes.ts` |
| `DATA-EXFIL` | `src/nanomind-core/compiler/semantic-compiler.ts`, `src/simulation/probes.ts` |
| `DATA-LEAK` | `src/hardening/nemoclaw-scanner.ts` |
| `MCP-SCOPE-LEAK` | `src/semantic/structural/mcp-config.ts` |
| `MONITORING-GAP` | `src/hardening/nemoclaw-scanner.ts` |
| `NETWORK-EXPOSURE` | `src/hardening/nemoclaw-scanner.ts` |
| `PERSIST` | `src/nanomind-core/analyzers/scope-analyzer.ts` |
| `SUPPLY-CHAIN` | `src/hardening/nemoclaw-scanner.ts`, `src/nanomind-core/compiler/semantic-compiler.ts` |

### The matrix's per-technique field

Each of the matrix's 61 techniques carries one `attackClass` value, 23
distinct values in all. Every one is a family code, not one of the ten
classes. The Matrix techniques column above reads each family's own
`techniques` list instead, because a technique can sit under several
families while its field names one.

## Keeping this file current

`__tests__/hardening/attack-family-census.test.ts` reads this file and fails
when a family in `TAXONOMY_MAP` or `FAMILY_CLASS` has no row, when a row's
class differs from what `getCanonicalClass` returns, when a fold row disagrees
with `FAMILY_FOLDS`, when a listed check id maps to a different family, or
when a family string set inline under `src/` is neither a row here nor listed
in the inline table with the files that set it. The Matrix techniques and
Registry columns are measurements at the commits named at the top; measure
them again when either register moves.
