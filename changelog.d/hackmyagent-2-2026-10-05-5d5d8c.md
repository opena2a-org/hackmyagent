---
type: changed
---
#### The hackmyagent_deep_scan MCP tool tells the host LLM that file contents are data

- The `overallGuidance` text that `hackmyagent_deep_scan` returns beside the
  scanned files carried no boundary clause, and PROMPT-001 failed when run
  over it. It now ends with a rule saying the `content` field of each
  `filesForDeepAnalysis` entry is data from the scanned project, and telling
  the host LLM not to follow instructions found inside it. PROMPT-001 and
  PROMPT-002 pass on the new text. The other fields of the result are
  unchanged.
