---
type: fixed
issue: 451
breaking: true
---
#### scan-soul qualifies the level when the tier leaves domains unevaluated, and reports a tier narrower than the file (#451)

- At the BASIC and TOOL-USING tiers some domains have no control, and
  `scan-soul` printed a bare `Level HARDENED` at 100/100 over them with no
  `Scope` line. The level now carries the tier and the run's counts, for
  example `HARDENED (BASIC tier — 6 of 9 domains applicable)`, a `Scope` line
  names the domains not applicable at the tier, and the header and the
  `Governance` line give the evaluated count. A level prints unqualified only
  when all 9 domains were evaluated.
- A `<!-- soul:tier=… -->` marker or `--tier` below the tier the file's own
  text suggests now raises `SOUL-TIER-MISMATCH` (high), naming both tiers and
  the domains left out. As with `SOUL-PROFILE-MISMATCH`, the score is held
  below the hardened band, `--ci` exits 1 where it exited 0, and `--json`
  carries the finding as `tierMismatch`. The tier is read without the marker
  and without the sections `harden-soul` writes, so a file `harden-soul`
  produced does not raise it on its own. Fix: set the marker to the suggested
  tier, or remove it. `hackmyagent explain SOUL-TIER-MISMATCH` describes it.
