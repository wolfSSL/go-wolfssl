# go-wolfssl CI image

Linux workflows pin `ghcr.io/wolfssl/go-wolfssl-ci` by its immutable image
digest. The image contains gcc-12 to 14, clang-16 to 18 with the sanitizer
runtimes, the autotools wolfSSL needs, OpenSSL, Go 1.21, the analysis Go
(1.26), the stable and oldstable Go releases, staticcheck, govulncheck,
actionlint, and shellcheck. Each Go toolchain lives under `/opt/go/<minor>`,
with `/opt/go/stable` and `/opt/go/oldstable` links, and
`.github/actions/setup-go-wolfssl` selects one by name.

From the repository root:

```sh
docker build --platform linux/amd64 \
    -f .github/docker/go-wolfssl-ci/Dockerfile -t go-wolfssl-ci .
docker run --rm --platform linux/amd64 go-wolfssl-ci go-wolfssl-ci-smoke
```

The Dockerfile-specific ignore file restricts the build context to the image
assets. Add shared dependencies here instead of installing them in workflow
jobs. Go patch releases and the stable and oldstable minors are resolved when
the image is rebuilt, and each archive is checked against go.dev's sha256.

In `wolfSSL/go-wolfssl`, `publish-ci-image.yml` runs on relevant pushes to
`master` and manual dispatches targeting `master`. It builds and smoke-tests
the image, then publishes `latest` and `sha-<commit>` tags. Publication is
serialized and uses the repository's `GITHUB_TOKEN`. The GHCR package must be
public so fork PRs can pull anonymously; the publisher checks this.

After publishing, a container job uses the build's output digest to repeat the
smoke checks in the GitHub runner environment.

Consumers should never fall back to building the image or installing packages.

Container jobs trust the mounted GitHub workspace after checkout so Git, and
Go's VCS stamping, can read a repository owned by the host runner. Their
explicit Bash command keeps the previous host shell's error behavior. The
sanitizer jobs run privileged so they can lower `vm.mmap_rnd_bits`.

To adopt a rebuilt image, inspect its `sha-<commit>` tag with
`docker buildx imagetools inspect` and copy the reported image digest into the
consumer workflows in a reviewed change. The publisher's smoke job tests the
new digest immediately, while consumer jobs keep using their reviewed digest.
To roll back, restore the previous digest in those workflows.
