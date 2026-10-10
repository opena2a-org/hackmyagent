---
type: fixed
---
#### The NanoMind classifier runs the model bytes it checked against their pins

- The classifier creates its ONNX session from the bytes of
  `nanomind-tme.onnx` and `nanomind-tme.onnx.data` that matched their pinned
  size and sha256, and parses `tokenizer.json` from the bytes it checked.
  Before, each file was checked and then opened again by path, and the ONNX
  runtime opened `nanomind-tme.onnx.data` from disk by itself, so a file that
  changed after its check was parsed unchecked. A file whose bytes no longer
  match its pin when it is loaded is not used, as when it fails the check
  that finds the cache.
