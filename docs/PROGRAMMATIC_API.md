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

## Reading `.hmaignore`

`parseHmaIgnore`, `matchHmaIgnore` and `isScopeChannel` are exported from the
package root, so a tool that honours the same `.hmaignore` file reads it with
the parser and tier order `secure` and `check` use.

```typescript
import { readFileSync } from 'node:fs';
import { parseHmaIgnore, matchHmaIgnore, isScopeChannel } from 'hackmyagent';
import type { ParsedHmaIgnore } from 'hackmyagent';

const today = new Date().toISOString().slice(0, 10); // UTC, YYYY-MM-DD
const parsed: ParsedHmaIgnore = {
  present: true,
  file: '.hmaignore',
  ...parseHmaIgnore(readFileSync('.hmaignore', 'utf-8'), today),
};
for (const e of parsed.errors) console.error(`.hmaignore:${e.line}: ${e.error}`);

const finding = { checkId: 'NEMO-009', file: 'danger.py' };
const match = matchHmaIgnore(structuredClone(finding), parsed);
if (match === null) {
  // No rule matches: the finding stays in the report.
} else if (isScopeChannel(match.channel)) {
  // `<path>` or `<path>:<CHECK-ID>`: the finding leaves the score and the exit code.
} else {
  // `!<CHECK-ID>`: listed as suppressed, still scored and still in the exit code.
}
```

- `today` is the UTC calendar date as `YYYY-MM-DD`, the date `secure` and
  `check` use. A rule with `expires:<YYYY-MM-DD>` is active while `today` is
  on or before that date; from the next day it is an `errors` entry, not a
  rule. A local date can apply a rule one day longer or shorter than the CLI
  does.
- `parseHmaIgnore` returns `{ rules, errors }`. `matchHmaIgnore` takes a
  `ParsedHmaIgnore`, which also holds `present` (whether the file exists) and
  `file` (`'.hmaignore'`, relative to the scanned directory), so add both to
  the parser's result as above. The loader that builds this object for the
  CLI is not exported from the package root. For a directory without the
  file, pass `{ present: false, file: '.hmaignore', rules: [], errors: [] }`.
- `matchHmaIgnore` can change the finding it is given. When `<path>` rules
  cover some but not all of the paths a finding names (`file` and
  `details.files`), the finding is kept and those two fields are rewritten to
  the paths that are not covered. Pass a deep copy, as `structuredClone` does
  above, when the original has to stay as it was.
- The third argument of `matchHmaIgnore` is a list of further paths treated as
  `<path>` rules, such as paths a caller excludes on its command line. A match
  through one of them has `line` undefined; any other match carries the
  1-based line of the rule.
- The tiers are applied in order: `<path>`, then `<path>:<CHECK-ID>`, then
  `!<CHECK-ID>`. Check ids and patterns compare case-insensitively, and `*`
  in a pattern matches any run of characters.

Plugin authoring: [`docs/PLUGIN_API.md`](docs/PLUGIN_API.md).
