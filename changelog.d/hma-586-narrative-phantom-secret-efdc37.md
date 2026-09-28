---
type: fixed
issue: 586
---
#### The package narrative no longer lists a phantom hardcoded secret (#586)

- **Credential forwarding and harvesting findings are not hardcoded secrets.** The package
  narrative (skill and MCP `check` targets, published to the Registry) reshaped every
  credential-class finding into a hardcoded-secret entry. `AST-CRED-002` and
  `SHELL-EXFIL-001` (class `CRED-EXFIL`) carry no value and no "Hardcoded <label>" name,
  so each became an entry of type `unknown` with an empty masked value, 0 characters, at
  critical — a secret the artifact does not contain. Findings of class `CRED-EXFIL` or
  `CRED-HARVEST` that carry no credential value are now left out of that list; one that
  does carry a value is kept. Verdicts, severities and scores are unchanged.
