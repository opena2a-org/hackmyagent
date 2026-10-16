# ONNX runtime telemetry

The NanoMind classifier that every `secure` scan runs executes in `onnxruntime-node`. Upstream's privacy notice says that official onnxruntime builds carry a telemetry client that is on by default, on macOS and Linux from 1.29.0. On the first session a process creates, the client writes a persistent device identifier and an event queue under the home directory, on macOS in `~/Library/Application Support/Microsoft/DeveloperTools/.onnxruntime`.

## What this tool does

- **Variable:** every load of the runtime goes through one loader that sets `ORT_DISABLE_TELEMETRY=1` in this tool's own process before the runtime loads. Upstream documents that the variable prevents the uploader, the events and the identifier.
- **Runtime version:** `package.json` declares `onnxruntime-node` `^1.27.0`, so a fresh install of this tool resolves the newest 1.x release. On 2026-10-17 that was 1.30.0, whose macOS and Linux libraries carry the client; 1.27.0, the version this repository's lockfile resolves, carries none. With 1.30.0 on macOS, a scan under an empty home directory wrote both files without the variable and nothing with it, measured on 2026-10-16.

The variable is set in this tool's process only. It does not change another program that loads onnxruntime.

## Check it yourself

```bash
npm ls -g onnxruntime-node   # the onnxruntime-node version a global install of hackmyagent resolved
ls "$HOME/Library/Application Support/Microsoft/DeveloperTools/.onnxruntime"   # macOS, after a scan
```

On a machine where no other program loads onnxruntime 1.29.0 or later, the second command reports that the directory does not exist.
