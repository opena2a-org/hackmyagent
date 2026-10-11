# NanoMind Core: Semantic Security Compiler

The foundational intelligence layer for HackMyAgent. Compiles raw artifacts into Abstract Security Trees (ASTs) that all analyzers query.

## Architecture

```
Artifact → Secure Ingestion → NanoMind Compiler → Signed AST → Analyzers → Findings
                 |                    |                            |
            Validate            Sanitize input              Verify AST
            Classify            Extract semantics            signature
            Hash                Classify intent              before use
                                Sign output
```

## Principles

1. **NanoMind is the foundation**: analyzers query the AST, not raw text
2. **Security-first**: input sanitized, ASTs signed, secrets redacted, integrity verified
3. **Defense-in-depth**: NanoMind can upgrade findings but NEVER suppress static analysis

## Components

### Ingestion (`ingestion/`)
- `artifact-parser.ts`: Validates, classifies, hashes artifacts
- `input-sanitizer.ts`: Strips prompt injection attempts targeting NanoMind

### Compiler (`compiler/`)
- `semantic-compiler.ts`: Produces signed SecurityASTs from artifacts

### Analyzers (`analyzers/`)
| Analyzer | Checks | What It Detects |
|----------|--------|-----------------|
| `capability-analyzer.ts` | AST-CAP-001 to 002, AST-EXFIL-001, AST-INJECT-001, AST-HEARTBEAT-001, AST-CRED-001, AST-PERSIST-001, AST-MANIP-001, AST-SCOPE-001 | Undeclared and unconstrained capabilities, exfiltration, injection surfaces, remote instruction fetch, credential harvesting, persistence, NanoMind manipulation, capability-purpose mismatch |
| `credential-analyzer.ts` | AST-CRED-001 to 003 | Credential exposure, forwarding, hardcoded secrets |
| `governance-analyzer.ts` | AST-GOV-001 to 005 | Governance gaps, weak constraints, override resistance |
| `scope-analyzer.ts` | AST-SCOPE-001 to 004 | Wildcard access and unbounded skill permissions, undeclared permissions, scope mismatch, adversarial configuration directives |
| `prompt-analyzer.ts` | AST-PROMPT-001 to 004 | Jailbreak susceptibility, capability creep, authority confusion |
| `code-analyzer.ts` | AST-CODE-001 to 003 | Command injection, unsafe deserialization, path traversal |
| `stego-analyzer.ts` | UNICODE-STEGO-001, UNICODE-STEGO-004 to 005 | Hidden Unicode (variation selectors, zero-width and bidi characters, tag characters, homoglyphs); separates emoji and i18n use from payload encoding |

AST-CRED-001 and AST-SCOPE-001 are emitted by both the capability analyzer and the credential or scope analyzer. Weak or missing constraints are reported by the governance analyzer (AST-GOV-002, AST-GOV-003), not the capability analyzer.

### Security (`security/`)
- `defense-in-depth.ts`: 7 rules (severity floor, benign consensus, secret redaction, AST integrity, training provenance, audit logging)
- `integrity-verifier.ts`: `verifyAll()` startup check, bounded hash-linked event log (diagnostic, unkeyed), manifest generation

### Bridge
- `scanner-bridge.ts`: Merges AST findings with static findings (defense-in-depth)

## Usage

```typescript
import { SemanticCompiler, analyzeCapabilities, analyzeGovernance } from './nanomind-core';

const compiler = new SemanticCompiler();
const { ast } = await compiler.compile(skillContent, 'my-skill.md');

// Analyzers query the AST, not raw text
const capFindings = analyzeCapabilities(ast);
const govFindings = analyzeGovernance(ast, compiler.verifyAST.bind(compiler));
```

## Tests

Tests live in `__tests__/nanomind-core/`. Count the test files with
`find __tests__/nanomind-core -name '*.test.ts' | wc -l`, and run them with:
```bash
npx vitest run __tests__/nanomind-core/
```
