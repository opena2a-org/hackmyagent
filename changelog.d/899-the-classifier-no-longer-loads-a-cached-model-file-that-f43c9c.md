---
type: fixed
issue: 899
---
#### The classifier no longer loads a cached model file that fails its pinned check when the download fails or is never run (#899)

- When a cached classifier model file does not match its pinned size and
  sha256 and the download that would replace it fails, a scan no longer loads
  that file. Before, a model directory other than the download directory,
  such as `~/.opena2a/nanomind/models`, still supplied the classifier after
  the failed download: its `tokenizer.json` was parsed and its weights were
  handed to the ONNX runtime, after the notice "The classifier did not run".
  A `tokenizer.json` that matches its pin is still used for vocabulary
  scoring when the weights beside it do not match theirs.
- `TMEClassifier.classify()` from `hackmyagent/nanomind-core`, which runs no
  download, loads cached files under the same check. Before, it parsed the
  `tokenizer.json` of the first model directory it found and handed the
  weights beside it to the ONNX runtime, whatever those files held.
