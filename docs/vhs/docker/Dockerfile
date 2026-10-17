# VHS 0.12.0 with the encode-context regression patched (evaluator.go renders with the
# cancelled recording context, so ffmpeg never starts and the error is swallowed).
# The patch is the committed file next to this Dockerfile; its sha256 goes into each sidecar.
FROM golang:1.26-trixie AS vhsbuild
ENV GOTOOLCHAIN=auto
COPY vhs-0.12.0-render-context.patch /tmp/vhs-0.12.0-render-context.patch
RUN git clone --depth 1 --branch v0.12.0 https://github.com/charmbracelet/vhs /src \
 && cd /src \
 && git apply /tmp/vhs-0.12.0-render-context.patch \
 && grep -n "v.Render(context.Background())" evaluator.go \
 && CGO_ENABLED=0 go build -ldflags "-X main.Version=v0.12.0+render-context-patch" -o /vhs .

FROM ghcr.io/charmbracelet/vhs:latest
COPY --from=vhsbuild /vhs /usr/bin/vhs
ARG NODE_VERSION=22.20.0
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends xz-utils ca-certificates curl procps gifsicle git >/dev/null \
 && curl -fsSL https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-arm64.tar.xz -o /tmp/node.tar.xz \
 && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 && rm /tmp/node.tar.xz \
 && node --version && npm --version && which ps gifsicle git
# The hackmyagent build the tapes type against. docs/vhs/record-secure.sh and record-detect.sh pass
# the version in package.json; with no argument the image carries 0.33.0, the build the committed
# docs/vhs/detect.json names. `none` installs no build: the render script then installs a packed
# tarball when the container starts.
ARG HMA_VERSION=0.33.0
RUN if [ "$HMA_VERSION" = "none" ]; then echo "no hackmyagent build in this image"; \
    else npm install -g "hackmyagent@${HMA_VERSION}" && hackmyagent --version; fi
ENV OPENA2A_TELEMETRY=off
ENV npm_config_update_notifier=false
ENV npm_config_yes=true
WORKDIR /work
ENTRYPOINT ["vhs"]
