---
type: fixed
issue: 1123
---
#### `check <URL>` shares no scan of a downloaded file, concurrent runs keep the integrity event log valid, and `detect` reads a process listing larger than 1 MiB (#1123)

- With contribution on and a terminal on standard input, `check` on an
  http(s) URL that is not a git URL sent the scan of the downloaded file to
  the community registry under the file's name: a URL ending in `/lodash`
  sent a scan named `lodash`, and one ending in `/` a scan named `download`.
  Such a scan is now neither sent nor queued. The scan of a cloned git
  repository is sent as before, named by host and path.
- Several `hackmyagent` processes started together under one HOME could
  write integrity events with the same `seq` and `prevHash`, and
  `EventChain.verify()` from `hackmyagent/nanomind-core` then reported the
  log as broken. An append now holds `<log>.lock` from reading the last event
  to writing its own; in the test, six processes appending 40 events each
  leave one chain that `verify()` accepts. `NANOMIND_EVENT_CHAIN_PATH`, when
  it holds an absolute path, sets where the log is written in place of
  `~/.nanomind/integrity-events.jsonl`.
- When `ps aux` printed more than 1 MiB, `detect --json` reported
  `"examined": 4, "total": 5` although `ps` ran. The listing is now read up
  to 256 MiB, and the same run reports `"examined": 5, "total": 5`. The
  NemoClaw process checks read `ps aux` with the same limit.
