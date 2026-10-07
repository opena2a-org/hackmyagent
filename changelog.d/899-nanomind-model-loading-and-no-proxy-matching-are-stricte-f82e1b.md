---
type: fixed
issue: 899
---
#### NanoMind model loading and NO_PROXY matching are stricter, and package.json checks keep their message when a directory could not be listed (#899)

- The classifier no longer loads model files from `./models` in the working
  directory, so a tree scanned from its own root cannot supply the classifier
  weights. A cached model file is used only when its size and sha256 match
  the pinned values; a cached file of the pinned size with different content
  is downloaded again. Before, a pinned `tokenizer.json` was enough for the
  files beside it to be loaded at their pinned sizes, whatever they held.
- The model download treats only a lone `*` in NO_PROXY as matching every
  host, as curl and Go do. Entries such as `.*`, `*.*`, `**` and `..*` sent
  every model request direct and now match no host, and brackets are
  accepted only around an IPv6 literal, so `[huggingface.co]:443` no longer
  matches `huggingface.co`.
- When a directory could not be listed, `secure` no longer adds "(a directory
  could not be listed — see SCAN-UNREAD-001)" to the passed CRED-003,
  DEP-002, DEP-003 and DEP-004 records. Those checks read only
  `package.json`, which a directory elsewhere in the tree cannot hide.
