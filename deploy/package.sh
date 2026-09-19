#!/bin/sh
# 本地发版封包（与 .github/workflows/release.yml 同构，无 CI 也可发版）。
#
# 产物（target/dist/）：
#   starskiff-<ver>-x86_64-windows.zip       starskiff.exe + starskiff-server.exe + wintun.dll + README
#   starskiff-<ver>-x86_64-linux-musl.tar.gz starskiff + starskiff-server + README
#
# 依赖：Node（web 构建）、cargo-zigbuild（musl 交叉：python -m pip install
# cargo-zigbuild ziglang）。版本号取自 cargo metadata，不在脚本里硬编码。
set -eu
cd "$(dirname "$0")/.."

VER=$(cargo metadata --no-deps --format-version 1 | sed 's/.*"version":"\([^"]*\)".*/\1/' | head -1)
case "$VER" in
  *-alpha*|*-beta*|*-rc*) ;;
  *) echo "警告：版本号 '$VER' 无预发布后缀（当前阶段约定 alpha）" ;;
esac
echo "== starskiff $VER 封包 =="

# 1) 管理页（release 构建经 rust-embed 编译期嵌入，必须先产出真实 dist
#    覆盖入库的占位页）。
echo "== [1/3] web 构建 =="
(cd crates/skiff-server/web && npm ci --no-fund --no-audit -s && npm run build -s)

# 2) 双 target release（Windows crt-static 已固化在 .cargo/config.toml）。
echo "== [2/3] 双 target 构建 =="
cargo build --release --workspace -q
cargo zigbuild --release --workspace --target x86_64-unknown-linux-musl

# 3) 打包。
echo "== [3/3] 打包 =="
DIST=target/dist
rm -rf "$DIST"
mkdir -p "$DIST/starskiff-$VER-windows-x64" "$DIST/starskiff-$VER-linux-x64"
cp target/release/starskiff.exe target/release/starskiff-server.exe "$DIST/starskiff-$VER-windows-x64/"
cp native/wintun/wintun.dll "$DIST/starskiff-$VER-windows-x64/"
cp README.md "$DIST/starskiff-$VER-windows-x64/"
cp target/x86_64-unknown-linux-musl/release/starskiff \
   target/x86_64-unknown-linux-musl/release/starskiff-server "$DIST/starskiff-$VER-linux-x64/"
cp README.md "$DIST/starskiff-$VER-linux-x64/"

(cd "$DIST" && powershell -NoProfile -Command \
  "Compress-Archive -Path 'starskiff-$VER-windows-x64' -DestinationPath 'starskiff-$VER-x86_64-windows.zip' -Force")
(cd "$DIST" && tar -czf "starskiff-$VER-x86_64-linux-musl.tar.gz" "starskiff-$VER-linux-x64")
rm -rf "$DIST/starskiff-$VER-windows-x64" "$DIST/starskiff-$VER-linux-x64"

echo "== 完成 =="
ls -la "$DIST"
