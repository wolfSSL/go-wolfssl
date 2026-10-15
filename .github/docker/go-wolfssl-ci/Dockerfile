# Shared dependencies for go-wolfssl Linux CI. Rebuild through publish-ci-image.yml.
FROM ubuntu:24.04

LABEL org.opencontainers.image.source="https://github.com/wolfSSL/go-wolfssl" \
      org.opencontainers.image.description="go-wolfssl Linux CI toolchains and test dependencies" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/opt/gopath \
    GOTOOLCHAIN=local \
    GOTELEMETRY=off \
    PATH=/opt/go-tools/bin:/opt/go/stable/bin:$PATH

# Package installation belongs here, rather than in individual CI jobs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential gcc-12 gcc-13 gcc-14 \
        clang clang-16 clang-17 clang-18 libclang-rt-18-dev llvm \
        autoconf automake libtool libtool-bin pkg-config m4 \
        git curl ca-certificates jq openssl iproute2 procps \
        nodejs python3 python3-yaml shellcheck \
        zip unzip xz-utils zstd file \
    && rm -rf /var/lib/apt/lists/*

# Go 1.21 (the CI floor), the analysis toolchain, and the stable and oldstable
# releases, resolved at image build time rather than downloaded in every job.
ARG ANALYSIS_GO=1.26
COPY .github/docker/go-wolfssl-ci/install-go.sh /tmp/install-go.sh
RUN /tmp/install-go.sh 1.21 "$ANALYSIS_GO" && rm /tmp/install-go.sh

# staticcheck v0.8.1 reads export data only up to Go 1.26; bump both together.
RUN GOBIN=/opt/go-tools/bin "/opt/go/$ANALYSIS_GO/bin/go" install honnef.co/go/tools/cmd/staticcheck@v0.8.1 \
    && GOBIN=/opt/go-tools/bin "/opt/go/$ANALYSIS_GO/bin/go" install golang.org/x/vuln/cmd/govulncheck@v1.8.0 \
    && GOBIN=/opt/go-tools/bin go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 \
    && prefetch=$(mktemp -d) && cd "$prefetch" \
    && go mod init prefetch && go get golang.org/x/term@v0.25.0 \
    && cd / && rm -rf "$prefetch" "$(go env GOCACHE)"

COPY .github/docker/go-wolfssl-ci/smoke-test.sh /usr/local/bin/go-wolfssl-ci-smoke
RUN chmod +x /usr/local/bin/go-wolfssl-ci-smoke && go-wolfssl-ci-smoke
