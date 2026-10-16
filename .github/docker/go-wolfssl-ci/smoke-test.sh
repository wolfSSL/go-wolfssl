#!/bin/bash
# Exercise the installed toolchains before an image is published.
set -euo pipefail

smoke_dir=$(mktemp -d)
trap 'rm -rf "$smoke_dir"' EXIT
cat > "$smoke_dir/main.c" <<'EOF'
int main(void)
{
    return 0;
}
EOF

for compiler in gcc gcc-12 gcc-13 gcc-14 clang clang-16 clang-17 clang-18; do
    "$compiler" --version | head -n 1
    "$compiler" -Wall -Wextra -Werror "$smoke_dir/main.c" -o "$smoke_dir/compiler-test"
    "$smoke_dir/compiler-test"
done
for sanitizer in address undefined memory; do
    clang -fsanitize="$sanitizer" "$smoke_dir/main.c" -o "$smoke_dir/sanitizer-test"
done

mkdir "$smoke_dir/cgo"
cat > "$smoke_dir/cgo/main.go" <<'EOF'
package main

// int answer(void) { return 42; }
import "C"

func main() {
	if C.answer() != 42 {
		panic("cgo")
	}
}
EOF
printf 'module smoke\n\ngo 1.21\n' > "$smoke_dir/cgo/go.mod"
for goroot in /opt/go/1.21 /opt/go/oldstable /opt/go/stable; do
    "$goroot/bin/go" version
    (cd "$smoke_dir/cgo" && "$goroot/bin/go" run .)
done
for tool in autoconf automake libtoolize make pkg-config git curl jq openssl \
            ss sysctl node python3 shellcheck zip unzip zstd llvm-symbolizer; do
    command -v "$tool"
done
python3 -c 'import yaml'
staticcheck -version
govulncheck -version
actionlint -version
test -d "$GOPATH/pkg/mod/golang.org/x/term@v0.25.0"
