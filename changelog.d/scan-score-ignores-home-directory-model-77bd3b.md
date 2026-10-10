---
type: fixed
---
#### A scan's score no longer depends on a model file in your home directory

- `secure` used to load a `nanomind-tme.bin` from `~/.opena2a/nanomind/models`, or from a sibling training checkout, whenever one was there, and let it decide an artifact's intent. No release pins that file, so the same tree scored differently on two machines: an older file there labelled the corpus SOUL fixtures `partial-controls-soul` and `permissive-overrides-soul` malicious, added AST-PROMPT-001, AST-PROMPT-003 and AST-PROMPT-004, and scored both 65 instead of 69.
- A scan no longer loads `nanomind-tme.bin` from that directory; the pinned classifier's files are still accepted from it only at their published size and sha256. Intent comes from the pinned classifier, whose files load only at their published size and sha256, so the result is the same under any home directory. On a machine without such a file nothing changes.
