---
type: fixed
---
#### `fix-all --with-aim` no longer replaces a signing identity it cannot read

- When the identity file in the user store existed but could not be read or
  parsed (a permission fault, a truncated write, a directory or a dangling
  link at its path), `fix-all --with-aim` generated a new Ed25519 key, wrote
  it over the file and reported the identity as `created`. The old private key
  was lost. The command now stops before any fix runs, exits 1, leaves the file
  as it is, and prints its path, the reason, an `ls -l` check and the way to
  recover it (for a permission fault, `chmod 600 <path>`). Once the file is
  readable again, the next run reuses the same key.
