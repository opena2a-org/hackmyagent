---
type: fixed
issue: 1045
---
- The Fix for a PEM private key found inside a file now says to remove the
  key block, generate a new key pair, install the new public key wherever
  the old one was authorized, revoke the old one, and keep the new private
  key outside the repository. It no longer cites `opena2a protect .`, and it
  names `git rm --cached` only when the file holds nothing but the key.
