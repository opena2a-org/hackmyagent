---
type: changed
issue: 447
breaking: true
---
#### Breaking: `check` no longer tells you not to depend on Flask; eval/exec findings in Python are graded by what the code runs (#447)

- `check pip:flask` reported `flask shell` honouring `PYTHONSTARTUP`
  (`src/flask/cli.py:1031`) and `Config.from_pyfile` as CRITICAL "Unsafe
  deserialization: eval/exec in Python" (NEMO-009), scored 68/100, exited 1
  and said "Do not depend on this package as-is." The Python finding is now
  named "eval/exec executes code". It is CRITICAL only when the argument on
  that line is, or is a name assigned earlier in the file from, a decoder or a
  network read: `b64decode`, `b32decode`, `a85decode`, `unhexlify`, a
  zlib/bz2/lzma decompress, `marshal.loads`, `codecs.decode`, `urlopen`,
  `requests.get`/`post`, `httpx` or a socket `recv`. The message names that
  source. Any other `eval`/`exec` is MEDIUM. `exec(base64.b64decode(...))` and
  `exec(urlopen(u).read())` stay CRITICAL. `check pip:flask` now scores 85/100
  and exits 0.
- No path decides the severity: files under `vendor/` and `tests/` are still
  scanned and graded the same way. In a test or build file, a NEMO-009 finding
  that is now MEDIUM shows as MEDIUM; it showed as LOW before, because only
  CRITICAL and HIGH findings in those files are lowered to LOW.
