#!/bin/sh
# Кросс-сборка релизных бинарников. Запускать с любой машины: Go умеет
# собирать под все цели сам, cgo нигде не нужен.
set -e

VERSION="${1:-dev}"
OUT="${OUT:-dist}"
LDFLAGS="-s -w -X main.version=${VERSION}"

mkdir -p "$OUT"
rm -f "$OUT"/fairway-*

build() {
  goos="$1"; goarch="$2"; suffix="$3"
  name="fairway-${goos}-${goarch}${suffix}"
  echo "  ${name}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/$name" ./cmd/fairway
}

echo "Сборка ${VERSION}:"
build linux   amd64 ""
build linux   arm64 ""
build windows amd64 ".exe"
build darwin  arm64 ""
build darwin  amd64 ""

echo
ls -la "$OUT"
