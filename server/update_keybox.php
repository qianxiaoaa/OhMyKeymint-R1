<?php
/**
 * 定时更新脚本（供 crontab 调用，建议 00:00 每天一次）：
 *   1. 按 config 依次拉取每个 enabled 上游源并解码
 *   2. 对每个候选做有效性校验（证书解析/链验证/过期/吊销）
 *   3. 每个源各取一份【最新有效】keybox，组成轮换池（不再按 priority 择优）：
 *      - 各成员分别做 Ed25519 签名，与自身内容一一对应
 *      - 每个成员存一份到 data/pool/<sha256>.xml
 *      - 轮换顺序 = 写入顺序，data/rotation.json 记 index
 *   4. 写 data/manifest.json 模板（pif 段保留）：manifest 里的 sha256/签名
 *      由 index.php 在响应时按「当前轮换成员」动态生成，客户端按现有契约校验
 *   （manifest.sha256 与签名必须匹配 action=keybox 返回的那份 keybox）。
 *
 * keybox.xml 与 manifest.json 都是私有数据，客户端经 public/index.php?action= 读取。
 *
 * 用法（由 update.sh 包装，宝塔计划任务调用）：
 *   sudo -u www /www/server/php/84/bin/php /path/to/server/update_keybox.php
 */

require_once __DIR__ . '/lib/sources.php';
require_once __DIR__ . '/lib/keybox.php';
require_once __DIR__ . '/lib/revocation.php';
require_once __DIR__ . '/lib/sign.php';
require_once __DIR__ . '/lib/rotation.php';

$cfg = require(getenv('OMK_SERVER_CONFIG') ?: __DIR__ . '/config.php');

$dataDir = $cfg['data_dir'];
@mkdir($dataDir, 0755, true);

$keyboxFile = $dataDir . '/' . $cfg['keybox_in'];
$manifest   = $dataDir . '/manifest.json';
$poolDir    = $dataDir . '/pool';

$ts = '[' . date('Y-m-d H:i:s') . ']';

// ---- 吊销名单：多源合并 + 永久名单 ----
// rev_fetch 会并行拉取全部源并合并（不是碰到第一个成功源就返回），
// 因此只要任意一个渠道收录了某个序列号，本轮就能看到。
$revInfo = rev_fetch(
    $cfg['revocation_sources'] ?? [],
    (string)($cfg['github_accel'] ?? ''),
    $dataDir . '/revocation.json',
    (int)($cfg['revocation_timeout'] ?? 20),
    (int)($cfg['revocation_max_age'] ?? 86400),
    !array_key_exists('http_verify_tls', $cfg) || !empty($cfg['http_verify_tls']),
    (array)($cfg['revocation_trusted_sources'] ?? [])
);
echo "{$ts} 吊销名单：{$revInfo['source']}，" . count($revInfo['entries']) . " 条"
    . ($revInfo['fresh'] ? '' : '（未能刷新）') . "\n";
foreach ($revInfo['tried'] as $t) { echo "    - {$t}\n"; }

// 把可信命中并入 append-only 永久名单：即使明天某个镜像失效，
// 已确认吊销的序列号也不会重新进入轮换池。
$permSync = rev_permanent_sync_online($cfg, $revInfo['entries']);
echo "{$ts} 永久吊销名单：新增 {$permSync['added']} 条，共 {$permSync['count']} 条（version {$permSync['version']}）\n";
$GLOBALS['OMK_PERM_SYNC'] = $permSync;

$revoked = kb_normalize_revoked(rev_blacklist_serials($cfg, $revInfo['entries']));
$GLOBALS['OMK_REV_INFO'] = $revInfo;

$modVer = $cfg['version'];
$modVc  = (int)$cfg['version_code'];

// ---- 1. 每个源各取一份最新有效 keybox，组成轮换池 ----
$pool = [];       // 轮换池成员
$candidates = []; // 健康报告（含失败项）
foreach ($cfg['sources'] as $name => $src) {
    if (empty($src['enabled'])) {
        continue;
    }
    echo "{$ts} 拉取源: {$name} ...\n";
    if (($src['type'] ?? '') === 'github_dir') {
        $pick = fetch_dir_source(
            $src,
            (string)$cfg['github_accel'],
            (int)$cfg['timeout'],
            (int)$cfg['download_retries'],
            15,
            function ($xml) use ($revoked) {
                $r = kb_validity_report($xml, $revoked);
                return !empty($r['ok']);
            },
            $cfg
        );
        if ($pick === false) {
            echo "    目录里没有取到可用 keybox，跳过\n";
            $candidates[] = ['source' => $name, 'ok' => false, 'why' => '目录取样失败'];
            continue;
        }
        echo "    取自 {$pick['file']}（试了 " . ($pick['tried'] ?? 1) . " 个）\n";
        $name .= '/' . preg_replace('/\.xml$/i', '', $pick['file']);
        $dec = $pick['keybox'];
    } else {
        $raw = http_get(
            (string)$src['url'],
            (string)($cfg['github_accel'] ?? ''),
            (int)$cfg['timeout'],
            (int)($cfg['download_retries'] ?? 3),
            !array_key_exists('http_verify_tls', $cfg) || !empty($cfg['http_verify_tls'])
        );
        if ($raw === false || $raw === '') {
            echo "    下载失败或为空，跳过\n";
            $candidates[] = ['source' => $name, 'ok' => false, 'why' => '下载失败'];
            continue;
        }
        $dec = decode_keybox($raw, $src['type']);
        if ($dec === false) {
            echo "    解码失败，跳过\n";
            $candidates[] = ['source' => $name, 'ok' => false, 'why' => '解码失败'];
            continue;
        }
    }
    if (!validate_keybox($dec)) {
        echo "    基础校验失败（非有效 keybox XML），跳过\n";
        $candidates[] = ['source' => $name, 'ok' => false, 'why' => '基础校验失败'];
        continue;
    }

    $rep = kb_validity_report($dec, $revoked);
    $sha = hash('sha256', $dec);
    if (!$rep['ok']) {
        $candidates[] = [
            'source' => $name,
            'ok'     => false,
            'why'    => implode('；', $rep['reasons']),
            'sha256' => $sha,
        ];
        echo "    *** 判定无效：" . implode('；', $rep['reasons']) . "\n";
        if (!empty($rep['warnings'])) {
            echo "    提示：" . implode('；', $rep['warnings']) . "\n";
        }
        continue;
    }
    echo "    通过：有效，剩余 {$rep['days_remaining']} 天，证书 " . count($rep['serials']) . " 个序列号\n";
    if (!empty($rep['warnings'])) {
        echo "    提示：" . implode('；', $rep['warnings']) . "\n";
    }

    $pool[] = [
        'source'    => $name,
        'sha256'    => $sha,
        'size'      => strlen($dec),
        'keybox'    => $dec,
        'validity'  => $rep,
        'serials'   => $rep['serials'],
    ];
    $candidates[] = [
        'source' => $name,
        'ok'     => true,
        'why'    => '',
        'sha256' => $sha,
    ];
}

// ---- 2. 人工固定 keybox（A/B 实验 / 回滚）：存在且有效时作为轮换池的成员 ----
// 不再「永远优先」：按用户要求改为轮换下发，固定 keybox 只是池子里的一份
// （排在最前，更新后第一次请求先下发它）。删掉该文件即恢复纯上游轮换。
$pinned = null;
$pinFile = (string)($cfg['keybox_pin'] ?? '');
if ($pinFile !== '' && is_file($pinFile) && @filesize($pinFile) > 0) {
    echo "{$ts} 检测到固定 keybox: {$pinFile}\n";
    $pinXml = (string)@file_get_contents($pinFile);
    if (!validate_keybox($pinXml)) {
        echo "{$ts} 固定 keybox 校验失败：基础校验失败，回退到自动择优\n";
    } else {
        $pinRep = kb_validity_report($pinXml, $revoked);
        if (!$pinRep['ok']) {
            echo "{$ts} 固定 keybox 校验失败：" . implode('；', $pinRep['reasons']) . "，回退到自动择优\n";
        } else {
            $pinned = [
                'source'    => 'pinned',
                'keybox'    => $pinXml,
                'sha256'    => hash('sha256', $pinXml),
                'validity'  => $pinRep,
                'serials'   => $pinRep['serials'],
            ];
            echo "{$ts} 固定 keybox 校验通过：有效，剩余 {$pinRep['days_remaining']} 天，加入轮换池\n";
        }
    }
}

// ---- 3. 决定本轮的交付集合（轮换池）----
// 固定 keybox 存在时排在最前，其后依次是每个 enabled 源的一份有效 keybox。
$members = [];
if ($pinned !== null) {
    $members[] = $pinned;
}
foreach ($pool as $m) {
    $members[] = $m;
}
if (empty($members)) {
    echo "{$ts} 本轮没有有效候选\n";
}

// ---- 4. 写成员文件 + 签名 + 轮换状态 ----
$secret = '';
$public = '';
if (empty($members)) {
    // 保留上一份 keybox 与轮换池；manifest 模板照常重建（含保留的 pif 段）。
    echo "{$ts} 无有效候选，保留上一次的 keybox 与轮换池\n";
    $health = [];
    foreach ($candidates as $c) {
        $health[] = ['source' => $c['source'], 'ok' => !empty($c['ok']), 'why' => $c['why'] ?? ''];
    }
    write_manifest_template($cfg, $dataDir, $manifest, $candidates, $health, $revoked, $modVer, $modVc, $public, true);
    exit(0);
}

@mkdir($poolDir, 0755, true);
$finalPool = [];
$memberContents = [];   // sha256 -> keybox 内容（data/keybox.xml 同步用）
$blocked = 0;
foreach ($members as $m) {
    // 写盘前的最终拦截。候选阶段已用本轮黑名单校验过一次，这里再以「永久名单
    // + 最新在线快照 + 手工列表」复查：客户端上报或其它进程可能刚刚把某个
    // 序列号提升为永久吊销，不能让它在同一轮里继续入池。
    $memberSerials = array_values(array_unique(array_filter(array_map('strval', $m['serials'] ?? []))));
    $permHit = $memberSerials === [] ? [] : rev_permanent_hits($cfg, $memberSerials);
    if (!empty($permHit)) {
        echo "{$ts} 拒绝入池 {$m['source']}：永久吊销名单命中 " . implode(',', array_keys($permHit)) . "\n";
        $candidates[] = ['source' => (string)$m['source'], 'ok' => false, 'why' => '永久吊销名单命中'];
        $blocked++;
        continue;
    }
    $lastCheck = kb_validity_report($m['keybox'], kb_normalize_revoked(rev_blacklist_serials($cfg, $revInfo['entries'])));
    if (empty($lastCheck['ok'])) {
        echo "{$ts} 拒绝入池 {$m['source']}：" . implode('；', $lastCheck['reasons'] ?? []) . "\n";
        $candidates[] = ['source' => (string)$m['source'], 'ok' => false, 'why' => '写盘前复检失败'];
        $blocked++;
        continue;
    }

    $memberFile = $poolDir . '/' . $m['sha256'] . '.xml';
    file_put_contents($memberFile, $m['keybox']);
    $memberContents[$m['sha256']] = $m['keybox'];
    // 每个成员用同一私钥单独签名；manifest 只引用当前成员的那份签名。
    $sig = '';
    try {
        if ($secret === '') {
            [$secret, $public] = sign_ensure_keys($cfg['keys_dir'], $cfg['sign_public_out'], $cfg['sign_secret_in']);
        }
        $sig = sign_data($secret, $m['keybox']);
        $m['signature'] = $sig;
    } catch (Throwable $e) {
        echo "    签名失败（sodium?）: " . $e->getMessage() . "\n";
    }
    $finalPool[] = [
        'source'      => (string)($m['source'] ?? 'pinned'),
        'sha256'      => $m['sha256'],
        'size'        => strlen($m['keybox']),
        'signature'   => $sig,
        // 序列号随成员保存：index.php 每次下发前无需再解析证书即可比对永久名单。
        'serials'     => $memberSerials,
        'days_remaining' => $m['validity']['days_remaining'] ?? null,
        'min_not_after'  => $m['validity']['min_not_after'] ?? null,
    ];
}

if (empty($finalPool)) {
    echo "{$ts} 所有候选都在最终拦截中被拒绝（{$blocked} 个），保留上一轮轮换池\n";
    $health = [];
    foreach ($candidates as $c) {
        $health[] = ['source' => $c['source'], 'ok' => !empty($c['ok']), 'why' => $c['why'] ?? ''];
    }
    write_manifest_template($cfg, $dataDir, $manifest, $candidates, $health, $revoked, $modVer, $modVc, $public, true);
    exit(0);
}

// 持久化轮换状态：保留 index（避免每次更新都从头开始，破坏轮换的连续性），
// 归一化到新池大小内。
$prev = omk_rotation_read($cfg);
$index = ($prev !== null) ? ((int)$prev['index'] % count($finalPool)) : 0;
$rot = [
    'updated_at' => date('Y-m-d H:i:s'),
    'pool'       => $finalPool,
    'index'      => $index,
];
omk_rotation_write($cfg, $rot);
echo "{$ts} 轮换池已写入 data/rotation.json（" . count($finalPool) . " 个成员，index={$index}）\n";

// 供 index.php 当前成员模板引用的清单
$currentSha = $finalPool[$index]['sha256'];
echo "{$ts} 首个要下发的成员: {$finalPool[$index]['source']} ({$currentSha})\n";

// 保留 data/keybox.xml：指向即将下发的首个成员（管理脚本/排障用，仅供参考）。
@file_put_contents($keyboxFile, $memberContents[$currentSha] ?? '');
echo "{$ts} data/keybox.xml 已同步为当前成员\n";

$health = [];
foreach ($candidates as $c) {
    $health[] = ['source' => $c['source'], 'ok' => !empty($c['ok']), 'why' => $c['why'] ?? ''];
}
write_manifest_template($cfg, $dataDir, $manifest, $candidates, $health, $revoked, $modVer, $modVc, $public, true);

// ============================================================
// 辅助函数
// ============================================================

/**
 * 写 manifest.json 模板。
 * 轮换模式下，manifest.keybox 的 sha256 / signature / validity 不在这里固化——
 * 由 index.php 在每次 action=manifest 时按「当前轮换成员」动态替换。
 * 这里保留结构、revocation、server 健康与 pif 段。
 *
 * @param array  $candidates 健康报告（含失败项）
 * @param array  $health     candidates 的 source/ok/why 子集
 * @param array  $revoked    规范化吊销序列号列表
 * @param bool   $keepPrev   为 true 时不覆盖旧 keybox/rotation（无有效候选分支用）
 */
function write_manifest_template(array $cfg, string $dataDir, string $manifestFile,
                                 array $candidates, array $health, array $revoked,
                                 string $modVer, int $modVc, string $signPublic = '', bool $keepPrev = true): void {
    $ri = $GLOBALS['OMK_REV_INFO'] ?? null;
    $status = rev_status($cfg);
    $revSection = [
        // 永久名单版本：客户端可据此判断自己缓存的吊销结论是否过期。
        'version'         => (int)$status['version'],
        'permanent_count' => (int)$status['permanent_count'],
        'permanent_updated_at' => $status['updated_at'],
        'report_count'    => (int)$status['report_count'],
        'pending_count'   => (int)$status['pending_count'],
        'report_threshold'=> (int)($cfg['report_threshold'] ?? 2),
        'report_url'      => rtrim((string)$cfg['base_url'], '/') . '/index.php?action=revocation_report',
        'checked'         => count($revoked),
        'fresh'           => (bool)($ri['fresh'] ?? false),
        'fetched_at'      => (int)($ri['fetched_at'] ?? 0),
        'count'           => (int)($status['cache_count'] ?? 0),
        'source'          => (string)($ri['source'] ?? ''),
        'tried'           => $ri['tried'] ?? [],
        'sources'         => $status['sources'],
    ];

    $keyboxEntry = [
        'url'         => rtrim($cfg['base_url'], '/') . '/index.php?action=keybox',
        'rotation'    => true,
        'sign_public' => $signPublic,
        // sha256 / signature / validity 由 index.php 按当前轮换成员动态填充
    ];

    $payload = [
        'version'      => $modVer,
        'version_code' => $modVc,
        'base_url'     => $cfg['base_url'],
        'keybox'       => $keyboxEntry,
        'server'       => [
            'updated_at'      => date('Y-m-d H:i:s'),
            'revoked_count'   => count($revoked),
            'sources'         => $health,
            'candidate_count' => count($candidates),
            'valid_count'     => count(array_filter($candidates, fn($c) => !empty($c['ok']))),
        ],
    ];
    $payload['keybox']['revocation'] = $revSection;
    // 云端通告：随 manifest 下发（index.php 每次请求时也会从 config.php 重新注入）。
    $payload['keybox']['notice'] = array_values((array)($cfg['notice'] ?? []));

    // 保留已有的 PIF 摘要字段（由 update_pif.php 写入），避免 keybox 更新冲掉它。
    if (is_file($manifestFile)) {
        $old = json_decode((string)@file_get_contents($manifestFile), true);
        if (is_array($old) && isset($old['pif'])) {
            $payload['pif'] = $old['pif'];
        }
    }

    @file_put_contents($manifestFile, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}
