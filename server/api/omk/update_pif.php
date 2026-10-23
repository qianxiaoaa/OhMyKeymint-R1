<?php
/**
 * PIF 指纹聚合更新（供 crontab 调用，建议 02:00 每天一次）：
 *   1. 依次从 config.pif_sources 的各上游来源抓取最新指纹
 *   2. 归一化 + 合并去重（只保留 Google Pixel、user/release-keys、合法补丁日期）
 *   3. 写出 public/pif/device_list.json 与 public/pif/device_prop/<product>.prop
 *      （web 根内静态文件，URL 契约 <base>/pif/... 不变）
 *
 * keybox 相关逻辑已全部移除：云端不负责 keybox 下发。
 *
 * 用法（由 update.sh 包装，宝塔计划任务调用）：
 *   sudo -u www /www/server/php/84/bin/php /path/to/server/api/omk/update_pif.php
 */

require_once __DIR__ . '/lib/http.php';
require_once __DIR__ . '/lib/pif_feed.php';

$cfg = require(getenv('OMK_SERVER_CONFIG') ?: __DIR__ . '/config.php');

$dataDir = rtrim((string)$cfg['data_dir'], '/');
@mkdir($dataDir, 0755, true);
$ts = '[' . date('Y-m-d H:i:s') . ']';

$all = [];
$health = [];
foreach (($cfg['pif_sources'] ?? []) as $name => $src) {
    if (empty($src['enabled'])) {
        continue;
    }
    echo "{$ts} PIF 源: {$name} ...\n";
    $res = pif_collect_source(
        $name,
        $src,
        (string)($cfg['github_accel'] ?? ''),
        (int)($cfg['timeout'] ?? 60),
        (int)($cfg['download_retries'] ?? 3)
    );
    echo "    {$res['detail']}\n";
    foreach ($res['profiles'] as $p) {
        $all[] = $p;
    }
    $health[] = [
        'source' => $name,
        'count'  => count($res['profiles']),
        'detail' => $res['detail'],
    ];
}

if (empty($all)) {
    echo "{$ts} 本轮没有取到任何指纹，保留上一份 feed\n";
    exit(0);
}

$written = pif_write_feed($cfg, $all);
echo "{$ts} 写出 feed：{$written['catalog']} 个设备\n";

// 聚合健康状态写回私有 data/（不对外公开，仅运维排障用）。
@file_put_contents(
    rtrim((string)$dataDir, '/') . '/pif_health.json',
    json_encode([
        'updated_at' => date('Y-m-d H:i:s'),
        'sources'    => $health,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
);
echo "{$ts} pif_health.json 已更新\n";