#!/bin/bash
# =========================================================
# OhMyKeymint 云端更新脚本 —— 宝塔计划任务执行此脚本
#
#   ./update.sh keybox   # 00:00 每天：拉取并择优 keybox（含吊销校验）
#   ./update.sh pif      # 02:00 每天：聚合 PIF 指纹
#   ./update.sh all      # 两个都跑
#
# 以 www 用户运行 PHP（与网站 PHP 进程同用户）。
# 请按你的实际环境修改下面两行。
# =========================================================
PHP=/www/server/php/85/bin/php
DIR=/www/wwwroot/omk.5ijxa.com/api/omk

MODE="${1:-all}"

# public/ 是 web 根（index.php + 静态 pif/），data/ 是私有数据，两者都要属 www。
chown -R www:www "$DIR/public" "$DIR/data" "$DIR/keys" 2>/dev/null
chmod -R 755 "$DIR/public" "$DIR/data" 2>/dev/null
chmod -R 700 "$DIR/keys" 2>/dev/null
# 上报去重盐只供服务端使用，收紧到仅属主可读。
[ -f "$DIR/data/report_salt" ] && chmod 600 "$DIR/data/report_salt" 2>/dev/null

cd "$DIR" || exit 1

run_php() {
    if [ "$(id -u)" = "0" ]; then
        sudo -u www "$PHP" "$1" >> "$DIR/update.log" 2>&1
    else
        "$PHP" "$1" >> "$DIR/update.log" 2>&1
    fi
}

case "$MODE" in
    keybox)
        run_php "$DIR/update_keybox.php"
        ;;
    pif)
        run_php "$DIR/update_pif.php"
        ;;
    *)
        run_php "$DIR/update_keybox.php"
        run_php "$DIR/update_pif.php"
        ;;
esac
