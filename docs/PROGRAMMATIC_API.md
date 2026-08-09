# Programmatic API

```typescript
import { HardeningScanner, AgentRuntimeProtection, AttackScanner } from 'hackmyagent';

import {
  SemanticCompiler,
  analyzeCapabilities,
  analyzeCredentials,
  analyzeGovernance,
  analyzeScope,
  analyzePrompt,
  analyzeCode,
  getTMEClassifier,
} from 'hackmyagent/nanomind-core';

const compiler = new SemanticCompiler();
const { ast } = await compiler.compile(skillContent, 'my-skill.skill.md');
// ast.intentClassification: 'benign' | 'suspicious' | 'malicious'
// ast.inferredCapabilities, ast.declaredConstraints, ast.inferredRiskSurface
const findings = analyzeCapabilities(ast);
```

Plugin authoring: [`docs/PLUGIN_API.md`](docs/PLUGIN_API.md).
