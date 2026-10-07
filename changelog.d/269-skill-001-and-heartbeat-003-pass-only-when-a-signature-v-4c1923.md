---
type: security
issue: 269
breaking: true
---
#### SKILL-001 and HEARTBEAT-003 pass only when a signature verifies (#269)

- `secure` read a skill or heartbeat as signed when its text contained
  `opena2a_signature:`, `signature:`, `-----BEGIN SIGNATURE-----` or
  `<!-- opena2a-guard hash=`, so a SKILL.md whose only relevant line was prose
  mentioning the field passed SKILL-001 with "Skill has cryptographic
  signature". A file now passes only when it ends in a signcrypt block whose
  `pinned_hash` is the sha256 of the content before the block and whose
  `opena2a_signature` verifies under the block's `signer` key. The pass message
  names that key. A bare marker, a block written without an identity
  (`opena2a_signature: unsigned`), or a file edited after it was signed reads
  unsigned, and the message says which.
- A skill or heartbeat that carried only a marker now fails SKILL-001 (medium)
  or HEARTBEAT-003 (high), so `secure` on such a tree can exit 1 where it
  exited 0.
- `secure --fix` no longer appends an `opena2a-guard` digest of the file to an
  unsigned skill and no longer reports SKILL-001 as fixed: a digest a file
  carries of itself proves nothing about who wrote it. SKILL-001 is now
  reported with `fixable: false`; sign with `hackmyagent fix-all --with-aim`.
- `fix-all` uses the same verifier. A file it pins without an identity reads
  unsigned until it is signed with `--with-aim`, and that remediation now reads
  "Pinned the SHA-256 hash of <file>; not signed, no identity to sign with"
  instead of claiming an Ed25519 signature.
