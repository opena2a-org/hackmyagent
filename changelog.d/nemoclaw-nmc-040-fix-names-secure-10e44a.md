---
type: fixed
---
- The NemoClaw scanner's HMA-NMC-040 finding names a command that scans the
  sandbox. Its fix read
  `docker exec "${CONTAINER:?set CONTAINER to the sandbox container name shown by docker ps}" npx hackmyagent scan --ci /app`,
  but `scan` takes a hostname, an IP address or a URL and has no `--ci`
  option, so the command exited 1 with `Cannot parse "/app" as a target`. The
  message and the fix now name the directory scanner:
  `docker exec "${CONTAINER:?set CONTAINER to the sandbox container name shown by docker ps}" npx hackmyagent secure --ci /app`.
