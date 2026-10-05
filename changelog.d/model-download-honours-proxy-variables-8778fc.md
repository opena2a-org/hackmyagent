---
type: fixed
---
#### The NanoMind model download goes through the proxy in HTTPS_PROXY, HTTP_PROXY and NO_PROXY

- On a network that reaches the internet only through a proxy, the first
  `secure` scan used to request the classifier model from Hugging Face
  directly, ignoring `HTTPS_PROXY` and `HTTP_PROXY`. The request failed and
  the scan fell back to vocabulary scoring. The download now goes through the
  proxy in `HTTPS_PROXY`, or in `HTTP_PROXY` when that is unset, and goes
  direct for hosts listed in `NO_PROXY`. TLS still runs end to end with
  Hugging Face inside the proxy tunnel, and each file is still checked
  against its pinned size and sha256.
- The stderr notice before the download names the proxy by host and port and
  the variable it came from. A user name or password in the proxy URL is
  sent to the proxy and never written to any output. A proxy the download
  cannot use, such as a `socks5://` URL, is reported on the failure line and
  no request is made.
- A proxy that accepts the connection and then sends nothing for 10 seconds
  is given up on, the same as a silent direct connection, and the scan
  continues on vocabulary scoring.
