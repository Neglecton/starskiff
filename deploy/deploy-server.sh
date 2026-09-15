#!/usr/bin/env bash
# Starskiff 服务端快速部署脚本（交互式；全部回车 = 默认一键部署）
#
# 用法：把本脚本与 starskiff-server 可执行文件放在同一目录，运行：
#   bash deploy-server.sh          （Linux / Windows Git Bash 通用）
#
# 行为：初始化数据库（仅首次，管理员令牌只显示一次）→ 前台运行服务器
#（Ctrl+C 停止）。本脚本【不】安装系统服务，仅打印安装命令。

set -euo pipefail

BIN_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BIN_DIR"

# ---- 定位可执行文件（Windows 下为 .exe） ----
EXE=""
for c in starskiff-server starskiff-server.exe; do
    if command -v "$c" >/dev/null 2>&1; then EXE="$c"; break; fi
    if [ -x "./$c" ]; then EXE="./$c"; break; fi
done
if [ -z "$EXE" ]; then
    echo "错误：未在 $BIN_DIR 找到 starskiff-server 可执行文件" >&2
    exit 1
fi

IS_WINDOWS=0
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac

# 绝对原生路径（供打印的系统服务安装命令使用；服务的工作目录不是本目录，
# 必须用绝对路径）。Git Bash 下 cygpath -w 转成 Windows 路径。
native_abs() {
    local p
    p="$(realpath -m "$1")"
    if [ "$IS_WINDOWS" -eq 1 ] && command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$p"
    else
        printf '%s\n' "$p"
    fi
}

echo "=============================================="
echo " Starskiff 服务端部署  （$(uname -s)）"
echo " 可执行文件: $BIN_DIR/$(basename "$EXE")"
echo "=============================================="

# ---- 交互式参数（回车 = 方括号内默认值） ----
read -rp "数据目录 [server-data]: " DATA_DIR
DATA_DIR="${DATA_DIR:-server-data}"
DB="$DATA_DIR/starskiff.sqlite"

read -rp "API 端口 [24930]: " API_PORT
API_PORT="${API_PORT:-24930}"
read -rp "UDP 中继端口 [24931]: " RELAY_UDP
RELAY_UDP="${RELAY_UDP:-24931}"
read -rp "TCP 中继端口 [24932]: " RELAY_TCP
RELAY_TCP="${RELAY_TCP:-24932}"
read -rp "启用 TLS（自动生成自签证书）？ [Y/n]: " TLS_ANS
NO_TLS_FLAG=""
case "$TLS_ANS" in
    n|N|no|NO) NO_TLS_FLAG="--no-tls" ;;
esac

mkdir -p "$DATA_DIR"

# ---- 首次运行：初始化并生成管理员令牌 ----
if [ ! -f "$DB" ]; then
    echo
    echo "---- 首次运行：初始化数据库 ----"
    # init 只在令牌不存在时生成并【仅显示一次】，请立即保存。
    "$EXE" init --db "$DB"
    echo "--------------------------------------------------"
    echo " 管理员令牌只显示一次，请保存到安全的地方！"
    echo " 之后每次 serve 启动时也会重新打印。"
    echo "--------------------------------------------------"
else
    echo "数据库已存在（$DB），跳过初始化。"
fi

# ---- 打印（不执行）系统服务安装命令 ----
DB_ABS="$(native_abs "$DB")"
LOG_ABS="$(native_abs "$DATA_DIR/server.log")"
SERVE_ARGS=(--db "$DB_ABS" --api-port "$API_PORT" --relay-udp "$RELAY_UDP" --relay-tcp "$RELAY_TCP" --log-file "$LOG_ABS")
[ -n "$NO_TLS_FLAG" ] && SERVE_ARGS+=("$NO_TLS_FLAG")
echo
echo "=================================================================="
echo " 可选：安装为系统服务（开机自启 + 崩溃自动重启，本脚本不会执行）"
echo " 在本目录、以管理员/root 身份运行："
echo
echo "   $EXE service install ${SERVE_ARGS[*]}"
echo
echo " 服务管理：$EXE service start | stop | status | remove"
echo "=================================================================="

# ---- 前台运行（Ctrl+C 停止） ----
RUN_ARGS=(--db "$DB" --api-port "$API_PORT" --relay-udp "$RELAY_UDP" --relay-tcp "$RELAY_TCP" --log-file "$DATA_DIR/server.log")
[ -n "$NO_TLS_FLAG" ] && RUN_ARGS+=("$NO_TLS_FLAG")
echo
echo "前台启动服务器（Ctrl+C 停止）……"
echo "启动后：API https://<本机IP>:$API_PORT （管理页 /admin/），中继 UDP $RELAY_UDP / TCP $RELAY_TCP"
echo "云服务器请在安全组放行 $API_PORT/tcp、$RELAY_UDP/udp、$RELAY_TCP/tcp"
echo
exec "$EXE" serve "${RUN_ARGS[@]}"
