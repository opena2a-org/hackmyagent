---
type: changed
issue: 734
---
#### A "without asking" instruction bounded by its gates is reported at low, and LIFECYCLE-003 is not applicable when the prompt has no safety instructions (#734)

- `SEM-INST-001` reported a `without asking`, `without confirmation` or
  `without approval` instruction at high even when the same paragraph bounded
  it, as in `Act on written recommendations without asking, inside the gates.
  Gates are never bypassed autonomously.` When the paragraph (consecutive
  non-blank lines) contains `inside the gates`, `within the gates`,
  `never bypass(ed)`, `hard stop(s)`, `requires approval` or
  `requires confirmation`, the finding is now reported at low, quotes the
  clause in its description and evidence, and its fix asks you to confirm the
  gates are enforced in configuration (permission deny rules, hooks), not only
  in prose. The finding is never cleared, because the same words can be
  written by an attacker. Without a bounding clause it stays at high, and the
  clause never lowers a different permissive pattern on the same line.
- `LIFECYCLE-003 Context window displacement` reported a failing high for a
  component such as a standalone `settings.json` that made up most of an
  assembled prompt with no `SOUL.md` or system prompt in it. With no safety
  instructions to displace, it is now recorded as not applicable and does not
  count against the score. An assembly that has a `SOUL.md` or system prompt
  is measured as before.
