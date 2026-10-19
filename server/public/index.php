<?php
/**
 * OhMyKeymint 前端控制器。
 *
 * 客户端按 action 参数取云端资源：
 *   /api/omk/index.php?action=manifest   返回当前轮换成员的清单（sha256 + 签名 + 有效性）
 *   /api/omk/index.php?action=keybox     按轮换顺序下发一份 keybox
 *   /api/omk/index.php?action=revocation_report  客户端吊销证据上报（POST/GET）
 *   /api/omk/index.php?action=stats      返回下发计数（网站首页用）
 *   /api/omk/index.php?action=pif&file=… 转发 PIF 指纹 feed 并计数
 *
 * keybox 轮换：
 *   - update_keybox.php 每轮从每个 enabled 源各取一份有效 keybox，组成
 *     data/rotation.json 的 pool，成员各自签名后存 data/pool/<sha256>.xml。
 *   - action=keybox 每次请求原子地「取当前成员并推进一格」，于是连续申请
 *     依次拿到不同的 keybox（按 pool 顺序轮转）。
 *   - action=keybox&offset=N 非破坏性取「当前指针之后第 N 个未吊销成员」，
 *     不改动轮换 index，供客户端抓取指定的第二份 keybox。
 *   - action=manifest 渲染的 sha256 / signature / validity 必须与接下来
 *     action=keybox 返回的成员一致，否则客户端签名校验会失败。这里不推进
 *     index（只有真正下发 keybox 才推进），所以 manifest 描述的就是下一次
 *     keybox 请求会拿到的那份；manifest 同时带 members 级 rotation.pool，
 *     pool[N] 与 action=keybox&offset=N 一一对应。
 *
 * 成功下发 keybox 或 PIF 指纹时都会在 data/counter.json 累加一次。
 *
 * PIF 指纹 feed 的 URL 契约不变（仍是 <base>/pif/device_list.json 与
 * <base>/pif/device_prop/<product>.prop）。nginx 把 /api/omk/pif/(.*) 重写成
 * /api/omk/index.php?action=pif&file=$1，于是 PIF 请求也经本控制器转发并实时
 * 计数，无需再解析 nginx 访问日志。
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/counter.php';
require_once dirname(__DIR__) . '/lib/rotation.php';
require_once dirname(__DIR__) . '/lib/keybox.php';
require_once dirname(__DIR__) . '/lib/sign.php';
require_once dirname(__DIR__) . '/lib/revocation.php';

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

$cfg = require dirname(__DIR__) . '/config.php';

$action = isset($_GET['action']) && is_string($_GET['action']) ? $_GET['action'] : '';

// 下发计数：只读，供网站首页 fetch
if ($action === 'stats') {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(omk_counter_read($cfg), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * 构造轮换成员的「未吊销」过滤器。
 *
 * 每次请求都以最终黑名单（手工列表 + 永久名单 + 在线快照）比对成员序列号。
 * 旧版 rotation.json 没有 serials 字段，现场解析成员文件兜底。
 * 返回 false 的成员既不会被 action=keybox 下发，也不会出现在 manifest 里。
 */
function omk_member_filter(array $cfg): callable
{
    $blacklist = [];
    foreach (kb_normalize_revoked(rev_blacklist_serials($cfg)) as $hex) {
        $blacklist[$hex] = true;
    }
    $dataDir = rtrim((string)$cfg['data_dir'], '/');

    return function (array $member) use ($blacklist, $dataDir): bool {
        $serials = $member['serials'] ?? [];
        if (!is_array($serials) || $serials === []) {
            $sha = (string)($member['sha256'] ?? '');
            if (!preg_match('/^[0-9a-f]{64}$/', $sha)) {
                return true; // 交给后面读取成员文件时按既有错误路径处理
            }
            $file = $dataDir . '/pool/' . $sha . '.xml';
            if (!is_file($file)) {
                return true;
            }
            $serials = [];
            foreach (kb_extract_certs((string)@file_get_contents($file)) as $c) {
                if (!empty($c['serial'])) {
                    $serials[] = (string)$c['serial'];
                }
            }
        }
        foreach ($serials as $serial) {
            $hex = kb_norm_serial((string)$serial);
            if ($hex !== '' && isset($blacklist[$hex])) {
                return false;
            }
        }
        return true;
    };
}

// ---- 客户端吊销证据上报（只收序列号 + keybox SHA-256 + 来源 + 检测时间） ----
if ($action === 'revocation_report') {
    header('Content-Type: application/json; charset=utf-8');

    $in = $_POST;
    if (empty($in)) {
        $ctype = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
        if (strpos($ctype, 'application/json') !== false) {
            $raw = file_get_contents('php://input', false, null, 0, 8192);
            $j = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
            if (is_array($j)) {
                $in = $j;
            }
        }
    }
    if (empty($in)) {
        // 兼容 GET：便于手动排查与小脚本上报
        $in = $_GET;
        unset($in['action']);
    }

    $res = rev_report_ingest($cfg, $in);
    http_response_code($res['accepted'] ? 200 : ($res['why'] === 'rate limited' ? 429 : 400));
    echo json_encode([
        'ok'         => (bool)$res['accepted'],
        'accepted'   => (bool)$res['accepted'],
        'pending'    => (bool)$res['pending'],
        'promoted'   => (bool)$res['promoted'],
        'version'    => (int)$res['version'],
        'checked_at' => date('c'),
        'why'        => (string)$res['why'],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * 校验 PIF 相对路径，只放行契约内的两种文件，杜绝目录穿越：
 *   device_list.json
 *   device_prop/<product>.prop
 */
function omk_pif_relpath(string $file): ?string
{
    if ($file === 'device_list.json') {
        return $file;
    }
    if (preg_match('#^device_prop/[A-Za-z0-9_]+\.prop$#', $file) === 1) {
        return $file;
    }
    return null;
}

// PIF 指纹 feed 转发 + 计数（URL 契约不变，nginx rewrite 到此）
if ($action === 'pif') {
    $file = isset($_GET['file']) && is_string($_GET['file']) ? $_GET['file'] : '';
    $rel = omk_pif_relpath($file);
    $path = $rel === null ? '' : rtrim((string)$cfg['pif_dir'], '/') . '/' . $rel;

    if ($path === '' || !is_file($path) || !is_readable($path)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "not found\n";
        exit;
    }

    $body = @file_get_contents($path);
    if ($body === false) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "read error\n";
        exit;
    }

    omk_counter_bump($cfg, 'pif');

    header('Content-Type: ' . (substr($rel, -5) === '.json' ? 'application/json; charset=utf-8' : 'application/octet-stream'));
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

// ---- keybox：按轮换顺序取当前成员并推进 ----
if ($action === 'keybox') {
    $filter = omk_member_filter($cfg);
    // 可选 offset：非破坏性读取轮换池里「当前指针之后第 N 个未吊销成员」，
    // 不改动 rotation index。带 offset 与不带 offset 的返回都经过同样的
    // 吊销最终拦截，已吊销成员永远不会被下发。
    $offset = null;
    if (array_key_exists('offset', $_GET)) {
        if (!is_string($_GET['offset']) || !preg_match('/^\d+$/', $_GET['offset'])) {
            http_response_code(400);
            header('Content-Type: text/plain; charset=utf-8');
            echo "bad request\n";
            exit;
        }
        $offset = (int)$_GET['offset'];
    }
    $picked = ($offset === null)
        ? omk_rotation_pick($cfg, $filter)
        : omk_rotation_peek($cfg, $filter, $offset);
    if ($offset !== null && $picked === null) {
        // offset 越界（池里没有第 N 个未吊销成员）：与「全部被吊销」一致，
        // 拒绝下发，不退回单文件模式。
        http_response_code(503);
        header('Retry-After: 3600');
        header('Content-Type: text/plain; charset=utf-8');
        echo "no valid keybox available\n";
        exit;
    }
    if (is_array($picked) && !empty($picked['blocked'])) {
        // 池里所有成员都进了吊销名单：宁可拒绝下发，也不把已知失效的 keybox 发出去。
        http_response_code(503);
        header('Retry-After: 3600');
        header('Content-Type: text/plain; charset=utf-8');
        echo "no valid keybox available\n";
        exit;
    }
    if ($picked === null) {
        // 没有轮换池（从未更新成功）：退回 data/keybox.xml 单文件。
        $legacy = rtrim((string)$cfg['data_dir'], '/') . '/' . ($cfg['keybox_in'] ?? 'keybox.xml');
        if (!is_file($legacy) || !is_readable($legacy)) {
            http_response_code(404);
            header('Content-Type: text/plain; charset=utf-8');
            echo "not available\n";
            exit;
        }
        $body = @file_get_contents($legacy);
        if ($body === false) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            echo "read error\n";
            exit;
        }
        // 单文件模式同样不能绕过最终拦截。
        $legacySerials = [];
        foreach (kb_extract_certs($body) as $c) {
            if (!empty($c['serial'])) {
                $legacySerials[] = (string)$c['serial'];
            }
        }
        if (!empty(rev_check(array_fill_keys(kb_normalize_revoked(rev_blacklist_serials($cfg)), true), $legacySerials))) {
            http_response_code(503);
            header('Retry-After: 3600');
            header('Content-Type: text/plain; charset=utf-8');
            echo "no valid keybox available\n";
            exit;
        }
        omk_counter_bump($cfg, 'keybox');
        header('Content-Type: application/xml; charset=utf-8');
        header('Content-Length: ' . strlen($body));
        echo $body;
        exit;
    }

    $sha = (string)($picked['member']['sha256'] ?? '');
    if ($sha === '' || !preg_match('/^[0-9a-fA-F]{64}$/', $sha)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "invalid rotation member\n";
        exit;
    }
    $memberFile = rtrim((string)$cfg['data_dir'], '/') . '/pool/' . $sha . '.xml';
    if (!is_file($memberFile) || !is_readable($memberFile)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "member file missing\n";
        exit;
    }
    $body = @file_get_contents($memberFile);
    if ($body === false) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "read error\n";
        exit;
    }

    omk_counter_bump($cfg, 'keybox');
    header('Content-Type: application/xml; charset=utf-8');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

// ---- manifest：按当前（下一次 keybox 将下发）成员动态渲染 ----
if ($action === 'manifest') {
    $dataDir = rtrim((string)$cfg['data_dir'], '/');
    $manifestFile = $dataDir . '/manifest.json';
    if (!is_file($manifestFile) || !is_readable($manifestFile)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "not available\n";
        exit;
    }
    $payload = json_decode((string)@file_get_contents($manifestFile), true);
    if (!is_array($payload)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "corrupt manifest\n";
        exit;
    }

    $rot = omk_rotation_read($cfg);
    $poolSize = ($rot !== null) ? count($rot['pool']) : 0;
    $peek = omk_rotation_peek($cfg, omk_member_filter($cfg));
    if ($poolSize > 0 && $peek === null) {
        // 池里全部成员都被吊销拦截：manifest 不能继续描述一份不会下发的 keybox。
        http_response_code(503);
        header('Retry-After: 3600');
        header('Content-Type: text/plain; charset=utf-8');
        echo "no valid keybox available\n";
        exit;
    }
    $member = null;
    $idx = 0;
    if ($peek !== null) {
        $member = $peek['member'];
        $idx = (int)$peek['index'];
        $poolSize = max(1, $poolSize);
    }

    if ($member !== null && !empty($member['sha256'])) {
        $memberFile = $dataDir . '/pool/' . $member['sha256'] . '.xml';
        $kb = is_file($memberFile) ? (string)@file_get_contents($memberFile) : '';
        $blacklist = kb_normalize_revoked(rev_blacklist_serials($cfg));
        $rep = $kb !== '' ? kb_validity_report($kb, $blacklist) : ['ok' => false, 'reasons' => ['成员文件缺失']];
        $revokedHits = empty($rep['serials']) ? []
            : array_keys(rev_check(array_fill_keys($blacklist, true), $rep['serials']));

        $payload['keybox']['sha256']      = $member['sha256'];
        $payload['keybox']['size']        = (int)($member['size'] ?? strlen($kb));
        $payload['keybox']['source']      = (string)($member['source'] ?? '');
        $payload['keybox']['signature']   = (string)($member['signature'] ?? '');
        $payload['keybox']['validity']    = [
            'level'          => $rep['ok'] ? ($rep['level'] ?? 'valid') : 'invalid',
            'ok'             => (bool)($rep['ok'] ?? false),
            'reasons'        => $rep['reasons'] ?? [],
            'warnings'       => $rep['warnings'] ?? [],
            'checked_at'     => date('Y-m-d H:i:s'),
            'min_not_after'  => $rep['min_not_after'] ?? null,
            'days_remaining' => $rep['days_remaining'] ?? null,
            'cert_count'     => $rep['cert_markers'] ?? null,
            'serial_count'   => count($rep['serials'] ?? []),
            'revoked'        => $revokedHits,
            'serials'        => $rep['serials'] ?? [],
            'chains'         => $rep['chains'] ?? [],
        ];
        $payload['keybox']['rotation'] = [
            'enabled'       => true,
            'pool_size'     => $poolSize,
            'current_index' => $idx,
        ];
        // 成员级清单：按轮换顺序（从当前成员起）把每个未吊销成员的 sha256 / 签名
        // / 有效性随清单一并下发，客户端无需额外状态即可校验并取「第二份 keybox」。
        // 契约：pool[0] 恒等于上面的 keybox.sha256；pool[N] 与 action=keybox&offset=N
        // 返回的成员一一对应（每个都先经吊销最终拦截，吊销成员不会出现在 pool 里）。
        $poolList = [];
        $snap = omk_rotation_snapshot($cfg, omk_member_filter($cfg));
        if ($snap !== null) {
            foreach ($snap['pool'] as $pm) {
                $pmFile = $dataDir . '/pool/' . $pm['sha256'] . '.xml';
                $pmKb = is_file($pmFile) ? (string)@file_get_contents($pmFile) : '';
                $pmRep = $pmKb !== '' ? kb_validity_report($pmKb, $blacklist)
                    : ['ok' => false, 'reasons' => ['成员文件缺失']];
                $pmHits = empty($pmRep['serials']) ? []
                    : array_keys(rev_check(array_fill_keys($blacklist, true), $pmRep['serials']));
                $poolList[] = [
                    'source'    => (string)$pm['source'],
                    'sha256'    => (string)$pm['sha256'],
                    'size'      => (int)$pm['size'],
                    'signature' => (string)$pm['signature'],
                    'validity'  => [
                        'level'          => $pmRep['ok'] ? ($pmRep['level'] ?? 'valid') : 'invalid',
                        'ok'             => (bool)($pmRep['ok'] ?? false),
                        'reasons'        => $pmRep['reasons'] ?? [],
                        'warnings'       => $pmRep['warnings'] ?? [],
                        'checked_at'     => date('Y-m-d H:i:s'),
                        'min_not_after'  => $pmRep['min_not_after'] ?? null,
                        'days_remaining' => $pmRep['days_remaining'] ?? null,
                        'cert_count'     => $pmRep['cert_markers'] ?? null,
                        'serial_count'   => count($pmRep['serials'] ?? []),
                        'revoked'        => $pmHits,
                    ],
                ];
            }
            $payload['keybox']['rotation']['pool']     = $poolList;
            $payload['keybox']['rotation']['excluded'] = (int)$snap['excluded'];
        }
    } else {
        // 兼容旧单文件模式：manifest 里已固化的 sha256/签名原样返回。
        $payload['keybox']['rotation'] = ['enabled' => false, 'pool_size' => 0, 'current_index' => 0];
    }

    // 吊销状态按当前文件实时渲染：永久名单/客户端上报可能刚在 update_keybox.php
    // 之外发生变化，模板里的旧值会让客户端误判为「已检查」。
    $status = rev_status($cfg);
    $rev = is_array($payload['keybox']['revocation'] ?? null) ? $payload['keybox']['revocation'] : [];
    unset($rev['sources']);
    $rev['version']          = (int)$status['version'];
    $rev['permanent_count']  = (int)$status['permanent_count'];
    $rev['permanent_updated_at'] = (string)$status['updated_at'];
    $rev['report_count']     = (int)$status['report_count'];
    $rev['pending_count']    = (int)$status['pending_count'];
    $rev['cache_count']      = (int)$status['cache_count'];
    $rev['cache_fetched_at'] = (int)$status['cache_fetched_at'];
    $rev['sources']          = $status['sources'];
    $payload['keybox']['revocation'] = $rev;

    // 云端通告：随 manifest 下发，客户端在每次获取 keybox 时展示。
    // 按 config.php 的 notice 数组逐条注入（模板里已有的旧值不保留）。
    $payload['keybox']['notice'] = array_values((array)($cfg['notice'] ?? []));

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// 其余 action 一律 404
http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
echo "not found\n";
exit;
