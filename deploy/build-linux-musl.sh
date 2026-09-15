#!/bin/sh
# Cross-build fully-static linux-x64 (musl) binaries inside a Rust container.
# NOTE: on Windows the no-Docker path is preferred:
#   python -m pip install cargo-zigbuild ziglang
#   cargo zigbuild --release --workspace --target x86_64-unknown-linux-musl
#
# Usage (from repo root; Git Bash needs MSYS_NO_PATHCONV=1):
#   MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/src" -w /src rust:1 \
#       sh deploy/build-linux-musl.sh
#
# If the registry pull stalls (proxy interference), use a mirror:
#   MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/src" -w /src \
#       docker.1ms.run/library/rust:1 sh deploy/build-linux-musl.sh
set -eu

apt-get update -qq && apt-get install -y -qq musl-tools >/dev/null
rustup target add x86_64-unknown-linux-musl

cargo build --release --workspace --target x86_64-unknown-linux-musl

mkdir -p publish/linux-musl
cp target/x86_64-unknown-linux-musl/release/starskiff publish/linux-musl/
cp target/x86_64-unknown-linux-musl/release/starskiff-server publish/linux-musl/
echo "== static check =="
ldd target/x86_64-unknown-linux-musl/release/starskiff || true
ls -la publish/linux-musl
