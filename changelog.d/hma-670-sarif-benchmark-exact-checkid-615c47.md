---
type: fixed
issue: 670
---
#### `secure --benchmark --format sarif` cites the records the control failed on (#670)

- The SARIF writer re-derived a control's records from `result.findings` by checkId, while
  the assessor evaluates `allFindings`. A failing record the plain scan does not list still
  failed its control, and SARIF then printed one location-less result for it. On an
  `mcp.json` with no tool whitelist, OASB-1 2.3 cited TOOL-001 and TOOL-002 in the JSON
  report and SARIF emitted one result with no file. The writer now reads the assessor's
  record set and joins each record by its exact evidence line, failing records only, so
  every cited record gets its own result and location, and a passed or fixed record of a
  cited checkId is never emitted as an `error`. Control statuses, compliance and the rating
  are unchanged. Regression: `__tests__/cli/sarif-benchmark-exact-checkid.test.ts`.
