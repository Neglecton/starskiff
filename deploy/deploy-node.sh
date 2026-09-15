#!/usr/bin/env bash
# Starskiff 节点快速部署脚本（交互式；已有配置则直接启动）
#
# 用法：把本脚本与 starskiff 可执行文件放在同一目录，运行：
#   bash deploy-node.sh              （Linux / Windows Git Bash 通用）
#
# 需要准备：服务器地址 + 一个注册令牌（skk_...，由服务端管理员在
# 管理页「注册令牌」或 `starskiff-server admin token create` 签发）。
# 行为：首次运行交互式完成 enroll 并生成 starskiff.json → 前台运行
# 节点（Ctrl+C 停止）。本脚本【不】安装系统服务，仅打印安装命令。

set -euo pipefail

BIN_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BIN_DIR"

# ---- 定位可执行文件（Windows 下为 .exe） ----
EXE=""
for c in starskiff starskiff.exe; do
    if command -v "$c" >/dev/null 2>&1; then EXE="$c"; break; fi
    if [ -x "./$c" ]; then EXE="./$c"; break; fi
done
if [ -z "$EXE" ]; then
    echo "错误：未在 $BIN_DIR 找到 starskiff 可执行文件" >&2
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
echo " Starskiff 节点部署  （$(uname -s)）"
echo " 可执行文件: $BIN_DIR/$(basename "$EXE")"
echo "=============================================="

CONFIG="starskiff.json"

# ---- 首次运行：交互式 enroll；已有配置则跳过 ----
if [ -f "$CONFIG" ]; then
    echo "已存在配置 $CONFIG —— 跳过注册直接启动（删除该文件可重新注册）。"
else
    while [ -z "${SERVER:-}" ]; do
        read -rp "服务器地址（如 https://1.2.3.4:24930）: " SERVER
    done
    while [ -z "${TOKEN:-}" ]; do
        read -rp "注册令牌（skk_...，服务端签发）: " TOKEN
    done
    read -rp "节点名 [$(hostname)]: " NAME
    NAME="${NAME:-$(hostname)}"

    echo
    echo "---- 注册（enroll）----"
    # 注册令牌若带 .指纹后缀会同时固定服务器证书；否则首连 TOFU 后自动固定。
    "$EXE" enroll --server "$SERVER" --token "$TOKEN" --name "$NAME" --config "$CONFIG"
fi

# ---- 打印（不执行）系统服务安装命令 ----
CONFIG_ABS="$(native_abs "$CONFIG")"
echo
echo "=================================================================="
echo " 可选：安装为系统服务（开机自启 + 崩溃自动重启，本脚本不会执行）"
echo " 在本目录、以管理员/root 身份运行："
echo
echo "   $EXE service install -c \"$CONFIG_ABS\""
echo
echo " 服务管理：$EXE service start | stop | status | remove"
if [ "$IS_WINDOWS" -eq 1 ]; then
    echo "（服务以 LocalSystem 运行；配置中的敏感字段已 DPAPI LocalMachine 密封，可直接读取）"
fi
echo "=================================================================="

# ---- 前台运行（Ctrl+C 停止） ----
echo
echo "前台启动节点（Ctrl+C 停止；网络成员与行为配置由服务器下发）。"
echo "状态查看：新开终端运行  $EXE status"
echo
exec "$EXE" up -c "$CONFIG"
