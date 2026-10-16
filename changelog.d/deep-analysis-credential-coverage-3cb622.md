---
type: changed
---
The LLM analysis in `secure --deep` and `secure --scan-depth deep` no longer reports credentials of a shape no local rule recognises in `.env`, `config.json`, `config.yaml`, `config.yml` and `settings.json` files. The static and semantic checks still examine these files on your machine, and `--json` lists each one found under `coverage.withheldFromLayer3`, as withheld by design rather than as a file that failed analysis.
