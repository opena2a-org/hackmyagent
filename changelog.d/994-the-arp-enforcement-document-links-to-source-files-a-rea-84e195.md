---
type: fixed
issue: 994
---
#### The ARP enforcement document links to source files a reader can open (#994)

- `docs/architecture/arp-enforcement.md` cited `src/arp/proxy/server.ts` and
  five other files that are no longer in this repository, so each one opened
  to "No such file or directory". The ARP runtime engine is part of
  `@opena2a/aim-sdk`, which `src/arp/index.ts` re-exports. The document now
  says so and links each cited file and its test file to its path in the SDK
  repository.
