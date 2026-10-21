<?php
/**
 * OhMyKeymint-R1 前端控制器。
 *
 * 站点只服务三个动作：
 *   /api/omk/index.php?action=stats   在线设备 + PIF 下发统计（网站首页用）
 *   /api/omk/index.php?action=report  客户端心跳上报（POST，每 30 分钟一次）
 *   /api/omk/index.php?action=pif&file=… 转发 PIF 指纹 feed 并计数
 *
 * keybox 不再由云端下发：客户端从固定的 GitHub 社区镜像源自行抓取校验安装，
 * 服务端没有任何 keybox / manifest / 吊销 / 轮换 / 签名逻辑。
 *
 * 在线设备数来自活跃心跳（lib/online.php），PIF 指纹 feed 的 URL 契约不变
 * （仍是 <base>/pif/device_list.json 与 <base>/pif/device_prop/<product>.prop）。
 * nginx 把 /api/omk/pif/(.*) 重写成 /api/omk/index.php?action=pif&file=$1，
 * 于是 PIF 请求经本控制器转发并实时计数，无需再解析 nginx 访问日志。
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/counter.php';
require_once dirname(__DIR__) . '/lib/online.php';

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

$cfg = require dirname(__DIR__) . '/config.php';

$action = isset($_GET['action']) && is_string($_GET['action']) ? $_GET['action'] : '';

// 只读统计：供网站首页 fetch，幂等。
if ($action === 'stats') {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=utf-8');
    $online = omk_online_read($cfg);
    echo json_encode([
        'devices'        => $online['devices'],
        'peak'           => $online['peak'],
        'keybox_distinct'=> $online['keybox_distinct'],
        'pif'            => omk_counter_read($cfg)['pif'],
        'product'        => 'OhMyKeymint-R1',
        'version'        => (string)$cfg['version'],
        'version_code'   => (int)$cfg['version_code'],
        'updated_at'     => date('Y-m-d H:i:s'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// 设备心跳上报（keystore 身份客户端，POST form/json）
if ($action === 'report') {
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

    $res = omk_online_ingest($cfg, $in);
    http_response_code($res['ok'] ? 200 : 400);
    echo json_encode([
        'ok'      => (bool)$res['ok'],
        'devices' => (int)$res['devices'],
        'peak'    => (int)$res['peak'],
        'interval' => (int)($cfg['online_interval'] ?? 1800),
        'checked_at' => date('c'),
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

    // 只对单个设备指纹的下载计数（device_list.json 是目录元数据，不计数），
    // 避免站点首页轮询把计数抬成虚高。
    if (strncmp($rel, 'device_prop/', 12) === 0) {
        omk_counter_bump($cfg, 'pif');
    }

    header('Content-Type: ' . (substr($rel, -5) === '.json' ? 'application/json; charset=utf-8' : 'application/octet-stream'));
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

// 其余 action 一律 404
http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
echo "not found\n";
exit;