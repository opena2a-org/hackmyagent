---
type: fixed
---
#### A first scan says on stderr that it is downloading the NanoMind model, in every output format

- `secure --json` (and every other machine format) on a machine with no
  cached model used to download the NanoMind classifier from Hugging Face
  with nothing on stderr; text mode printed a size that no longer matched
  the files. Before the first request, stderr now names the files' total
  size, the hosts (huggingface.co and Hugging Face's content CDN), the cache
  directory, that the download happens once per cache, and, on `secure`,
  the `--static-only` flag that skips it. One line follows saying the model
  was downloaded and verified, or that the download failed, why, and that
  the scan used vocabulary scoring instead. A run with the model already
  cached prints nothing. stdout is unchanged.
- Each downloaded file is now checked against its pinned byte count as well
  as its sha256, and redirects are followed only to huggingface.co and
  hosts under hf.co.
