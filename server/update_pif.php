<?php
/**
 * PIF 指纹聚合更新（供 crontab 调用，建议 02:00 每天一次）：
 *   1. 依次从 config.pif_sources 的各上游来源抓取最新指纹
 *   2. 归一化 + 合并去重（只保留 Google Pixel、user/release-keys、合法补丁日期）
 *   3. 写出 public/pif/device_list.json 与 public/pif/device_prop/<product>.prop
 *      （web 根内静态文件，URL 契约 <base>/pif/... 不变）
 *   4. 把摘要写回 data/manifest.json 的 pif 段（保留 keybox 段不动）
 *
 * 用法（由 update.sh 包装，宝塔计划任务调用）：
 *   sudo -u www /www/server/php/84/bin/php /path/to/server/update_pif.php
 */

require_once __DIR__ . '/lib/sources.php';
require_once __DIR__ . '/lib/pif_feed.php';
require_once __DIR__ . '/lib/sign.php';

$cfg = require(getenv('OMK_SERVER_CONFIG') ?: __DIR__ . '/config.php');

$dataDir = $cfg['data_dir'];
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

// 摘要写回 manifest.json（保留 keybox 段）
$manifestFile = $dataDir . '/manifest.json';
$payload = ['version' => $cfg['version'], 'version_code' => (int)$cfg['version_code'], 'base_url' => $cfg['base_url']];
if (is_file($manifestFile)) {
    $old = json_decode((string)@file_get_contents($manifestFile), true);
    if (is_array($old)) {
        $payload = $old;
    }
}
$payload['pif'] = [
    'updated_at'    => date('Y-m-d H:i:s'),
    'device_count'  => $written['catalog'],
    'catalog_url'   => rtrim($cfg['base_url'], '/') . '/pif/device_list.json',
    'profile_url'   => rtrim($cfg['base_url'], '/') . '/pif/device_prop/{product}.prop',
    'sources'       => $health,
];
@file_put_contents($manifestFile, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
echo "{$ts} manifest.json 已更新 pif 段\n";
