---
type: fixed
issue: 1059
---
#### The `secure` recording's sidecar drops `scriptSha256`, a second copy of the tape hash (#1059)

- `docs/vhs/secure.json` carried a `scriptSha256` field holding the sha256 of
  `docs/vhs/secure.tape`, the same value as `tapeSha256`. It matched neither
  `docs/vhs/record-secure.sh` nor `docs/vhs/setup-lab.sh`. The sidecar no
  longer carries the field and `docs/vhs/record-secure.sh` no longer writes
  it. The hashes the sidecar keeps are `tapeSha256` for the tape,
  `fixtureSha` for `docs/vhs/setup-lab.sh` and `vhsPatchSha256` for the VHS
  patch.
