---
type: fixed
issue: 893
---
#### NanoMind daemon start and model download: tighter checks and an accurate proxy notice (#893)

- A scan starts the NanoMind daemon only from a `bin` file inside the
  installed `@nanomind/daemon` package. A `bin` value such as `../../x.js`, or
  a link that leads out of the package, used to name the file the Node binary
  ran; such a package is now not started.
- A cached classifier model file whose size differs from its pinned size, for
  example one left short by a process killed during the download, is
  downloaded again with the usual stderr notice. It used to be loaded on every
  later scan, with no download and no notice.
- The model download follows a redirect to a host under `huggingface.co`, such
  as `cdn-lfs.huggingface.co`, as well as to one under `hf.co`. A redirect to
  the former used to fail the download.
- The download notice names the proxy for every host the download can reach,
  not only `huggingface.co`. When `NO_PROXY` sends some of them direct, as
  `NO_PROXY=huggingface.co` or `NO_PROXY=.hf.co` does, it names the proxy "for
  the hosts NO_PROXY does not cover". It used to name no proxy while the CDN
  requests went through one, or name a proxy they did not use.
- A `NO_PROXY` entry with an IPv6 address, with or without brackets and a
  port (`[::1]:443`, `[::1]`, `::1`), now matches that address. It used to
  match only when written as `[::1]` with no port.
