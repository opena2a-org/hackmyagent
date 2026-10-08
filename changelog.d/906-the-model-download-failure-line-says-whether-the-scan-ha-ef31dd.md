---
type: fixed
issue: 906
---
#### The model download failure line says whether the scan has vocabulary scoring, and cached model files are hashed once per process (#906)

- When the NanoMind model download failed and no tokenizer that passes its
  pinned check was cached (an empty cache, or a cached `tokenizer.json` with
  another sha256), the line on stderr said "this scan uses vocabulary
  scoring", while the classifier answered benign without scoring anything.
  The line now says the scan has no vocabulary scoring either. With a pinned
  tokenizer cached, it still says the scan uses vocabulary scoring.
- Each classifier that found a model cache read and hashed about 8.7 MB of
  model files, and a download hashed them again. Each file is now hashed once
  per process, and again only after it changes.
