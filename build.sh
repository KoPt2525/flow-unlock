#!/bin/sh
# Cross-compile flow-local for common OpenWrt targets.
# Run on a dev machine with Go >= 1.24 installed. Outputs to ./dist/.
set -e
cd "$(dirname "$0")"

OUT=dist
mkdir -p "$OUT"

build() {
    name="$1"; shift
    echo "==> $name"
    env CGO_ENABLED=0 GOOS=linux "$@" go build -trimpath -ldflags="-s -w" -o "$OUT/$name" .
}

build flow-local-linux-arm64  GOARCH=arm64
build flow-local-linux-armv7  GOARCH=arm GOARM=7
build flow-local-linux-mips    GOARCH=mips GOMIPS=softfloat
build flow-local-linux-mipsle  GOARCH=mipsle GOMIPS=softfloat
build flow-local-linux-amd64  GOARCH=amd64

echo ""
echo "Built binaries in $OUT/:"
ls -la "$OUT"
