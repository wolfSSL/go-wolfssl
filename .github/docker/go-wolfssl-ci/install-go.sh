#!/bin/bash
# Install the newest patch of each requested Go minor, plus the current stable
# and oldstable minors, under /opt/go/<minor>, checked against go.dev's sha256.
set -euo pipefail

releases=$(mktemp)
trap 'rm -f "$releases"' EXIT
curl --fail --silent --show-error --location \
    'https://go.dev/dl/?mode=json&include=all' -o "$releases"

mapfile -t latest < <(jq -r '[.[] | select(.stable) | .version
    | capture("^go(?<m>[0-9]+\\.[0-9]+)").m] | unique
    | sort_by(split(".") | map(tonumber)) | reverse | .[0:2][]' "$releases")
test "${#latest[@]}" -eq 2

mkdir -p /opt/go
for minor in $(printf '%s\n' "$@" "${latest[@]}" | sort -u); do
    read -r archive sha < <(jq -r --arg re "^go${minor//./\\.}\\.[0-9]+$" '
        [.[] | select(.stable and (.version | test($re)))] | first | .files[]
        | select(.os == "linux" and .arch == "amd64" and .kind == "archive")
        | [.filename, .sha256] | @tsv' "$releases")
    test -n "$archive" && test -n "$sha"
    curl --fail --silent --show-error --location \
        "https://go.dev/dl/$archive" -o /tmp/go.tar.gz
    echo "$sha  /tmp/go.tar.gz" | sha256sum --check -
    mkdir "/opt/go/$minor"
    tar -xzf /tmp/go.tar.gz -C "/opt/go/$minor" --strip-components=1
    rm /tmp/go.tar.gz
done
ln -s "${latest[0]}" /opt/go/stable
ln -s "${latest[1]}" /opt/go/oldstable
