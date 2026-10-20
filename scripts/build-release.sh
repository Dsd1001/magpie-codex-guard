#!/bin/sh
# Build standalone executable artifacts to be bundled by the Magpie Node plugin.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p bin dist
for target in linux-amd64 linux-arm64 darwin-arm64; do
  GOOS=${target%-*}
  GOARCH=${target#*-}
  printf 'Building %s / %s...\n' "$GOOS" "$GOARCH"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags="-s -w" -o "bin/codex-guard-$GOOS-$GOARCH" ./cmd/codex-guard
done
printf 'Packing Magpie plugin...\n'
npm pack --pack-destination dist
printf 'Release package(s):\n'
ls -lh dist/*.tgz
