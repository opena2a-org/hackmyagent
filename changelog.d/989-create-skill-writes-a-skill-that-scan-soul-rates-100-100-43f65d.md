---
type: fixed
issue: 989
---
#### `create-skill` writes a skill that `scan-soul` rates 100/100, and signs SKILL.md (#989)

- `scan-soul` on a skill fresh from `create-skill` reported Governance 26/100,
  and `harden-soul --dry-run` listed nine sections to add. The generated
  SOUL.md now carries the nine governance sections `harden-soul` writes, each
  after the skill's own rules for that domain, with the tier and profile
  pinned. `scan-soul` reports 100/100 and `harden-soul` has nothing to add.
- `secure` on a fresh skill reported AST-GOV-001 (no constraint for Action
  Reversibility or Identity Disclosure) and AST-PROMPT-004 (trust hierarchy
  only in SOUL.md). SOUL.md now has an Action Reversibility section and
  SKILL.md states its own trust hierarchy, so neither is reported. A skill that
  calls an external API also carried AST-GOV-002 on a sentence the generator
  wrote; that sentence now reads "must go to declared endpoints only".
- `create-skill` now signs SKILL.md, so `secure` no longer reports SKILL-001
  (Unsigned Skill) on a fresh skill. It signs with the identity
  `fix-all --with-aim` uses for the directory: an Ed25519 key created when the
  directory has none and stored outside it, under
  `$OPENA2A_HOME/projects/<key>/aim/` (default `~/.opena2a`). The run prints
  the identity file's path. `--no-sign` writes the skill unsigned and creates
  no identity. When the identity cannot be created or used, the skill is
  written unsigned and the run says why. An edit to SKILL.md invalidates the
  signature; `fix-all <dir> --with-aim` signs it again.
- On the description "Summarise a Markdown file the user names", `secure` went
  from 76/100 with seven findings to 84/100 with four. SUPPLY-001, SUPPLY-002,
  SUPPLY-004 and GIT-001 are still reported on a fresh skill.
- `harden-soul` wrote two sentences that `secure` then reported as AST-GOV-002
  (Weak Constraint Enforceability): "Never bypass authentication or
  authorization mechanisms" and "how the system will notify user". The three
  rules under Safety Immutables now begin "Must never", and the second sentence
  reads "must notify user". A file hardened by an earlier version keeps the
  lines it has.
