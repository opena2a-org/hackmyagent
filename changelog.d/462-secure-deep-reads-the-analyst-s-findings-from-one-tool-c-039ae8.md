---
type: changed
issue: 462
---
#### `secure --deep` reads the analyst's findings from one tool call, never from the reply text (#462)

- Layer 3 used to ask the analyst for a JSON array in its reply and then extract that array from the text: a reply that was itself the array, or the last fenced block in the reply, was read as the answer. The analysis request now offers one `report_findings` tool and requires the analyst to call it exactly once, and Layer 3 reads that call's input, which the API returns already parsed. The three system prompts no longer ask for a JSON array.
- A reply that carries no `report_findings` call, carries more than one, stops at the output limit, is declined, or holds an entry with no severity or description is reported for that file as `SEM-LLM-NOT-ANALYZED`, a gap in coverage, and is not read as a file with no findings. A reply whose text is a bare JSON array is one of these: before, it was read as the answer.
- The cache key now covers the tool definition as well as the system prompt, so a result cached by an earlier version is not replayed and the file is analyzed again.
