<?php
/**
 * PIF 指纹聚合 —— 把上游多个来源的 Pixel 指纹归一化成 OMK 客户端可直接消费的
 * feed：
 *   public/pif/device_list.json          [{"model":"Pixel 6","product":"oriole"}, ...]
 *   public/pif/device_prop/<product>.prop FINGERPRINT=...\nMANUFACTURER=...\n...
 *
 * 这两份文件是 web 根内的静态文件（config.pif_dir），URL 契约不变。
 *
 * 上游来源（config.pif_sources）目前都是 GitHub 仓库的最新 release，资产里可能是
 * 扩展 PIF JSON（Elcapitanoe / xprateek 生成器）或 .prop 文本；本模块两种都解析，
 * 解析不出 Google Pixel 指纹的资产直接跳过。
 *
 * 归一化规则与 OMK 客户端契约严格对齐（见 pif-common/src/lib.rs）：
 *   - 只保留 Google（BRAND=google、MANUFACTURER=Google）设备；
 *   - 指纹必须是 8 段、且 build_type=user、tags=release-keys；
 *   - SECURITY_PATCH 必须是合法 YYYY-MM-DD；
 *   - product 必须是小写字母/数字/下划线。
 * 不合规的记录被丢弃，避免把坏指纹下发到设备。
 */

/** 下载并 json_decode（失败返回 null） */
function pif_fetch_json(string $url, string $accel, int $timeout, int $retries = 2) {
    $raw = http_get($url, $accel, $timeout, $retries);
    if ($raw === false) return null;
    $j = json_decode($raw, true);
    return is_array($j) ? $j : null;
}

/**
 * 取仓库最新 release 的 tag + 资产列表。
 * 优先用 GitHub API（每天几次调用，远低于未认证限额），失败再退回 HTML 抓取
 * （releases/latest 会 302 到具体 tag，expanded_assets 页面列出资产链接）。
 *
 * @return array{tag:string,assets:array<int,array{name:string,url:string}>}|null
 */
function gh_latest_release(string $repo, string $accel, int $timeout): ?array {
    $api = 'https://api.github.com/repos/' . $repo . '/releases/latest';
    $j = pif_fetch_json($api, $accel, $timeout, 2);
    if (is_array($j) && !empty($j['tag_name'])) {
        $assets = [];
        foreach (($j['assets'] ?? []) as $a) {
            if (!is_array($a)) continue;
            $name = (string)($a['name'] ?? '');
            $url  = (string)($a['browser_download_url'] ?? '');
            if ($name !== '' && $url !== '') $assets[] = ['name' => $name, 'url' => $url];
        }
        return ['tag' => (string)$j['tag_name'], 'assets' => $assets];
    }

    // ---- HTML 兜底 ----
    $html = http_get('https://github.com/' . $repo . '/releases/latest', $accel, $timeout, 2);
    if ($html === false) return null;
    if (!preg_match('#/releases/tag/([^"\s/]+)#', $html, $m)) return null;
    $tag = $m[1];

    $assets = [];
    $expanded = http_get(
        'https://github.com/' . $repo . '/releases/expanded_assets/' . rawurlencode($tag),
        $accel,
        $timeout,
        2
    );
    if ($expanded !== false
        && preg_match_all('#href="(/[^"]+/releases/download/[^"]+)"#', $expanded, $am)) {
        foreach ($am[1] as $path) {
            $name = basename($path);
            $assets[] = ['name' => $name, 'url' => 'https://github.com' . $path];
        }
    }
    return ['tag' => $tag, 'assets' => $assets];
}

/** 指纹解析成 8 段，失败返回 null */
function pif_parse_fingerprint(string $fp): ?array {
    $fp = trim($fp);
    if ($fp === '' || strpos($fp, ' ') !== false) return null;
    $colon = explode(':', $fp);
    if (count($colon) !== 3) return null;
    $identity = explode('/', $colon[0]);
    $build    = explode('/', $colon[1]);
    $variant  = explode('/', $colon[2]);
    if (count($identity) !== 3 || count($build) !== 3 || count($variant) !== 2) return null;
    return [
        'brand'       => $identity[0],
        'product'     => $identity[1],
        'device'      => $identity[2],
        'release'     => $build[0],
        'id'          => $build[1],
        'incremental' => $build[2],
        'build_type'  => $variant[0],
        'tags'        => $variant[1],
    ];
}

/** 校验 product slug（与 OMK validate_product 一致） */
function pif_valid_product(string $p): bool {
    if ($p === '' || strlen($p) > 126 || preg_match('/[^a-z0-9_]/', $p)) return false;
    return (bool)preg_match('/^[a-z0-9]/', $p);
}

/** 校验展示值（与 OMK validate_display_value 一致） */
function pif_valid_display(string $v): bool {
    if ($v === '' || strlen($v) > 126 || trim($v) !== $v) return false;
    return preg_match('/^[A-Za-z0-9 _.\-+()]+$/', $v) === 1;
}

/** 校验 YYYY-MM-DD */
function pif_valid_date(string $d): bool {
    if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $d, $m)) return false;
    return checkdate((int)$m[2], (int)$m[3], (int)$m[1]);
}

/**
 * 把一组原始字段（来自 JSON 或 prop）归一化成内部记录。
 * @param array $f 至少含 FINGERPRINT/MANUFACTURER/MODEL/SECURITY_PATCH
 * @param int   $priority 来源优先级（越小越优先）
 * @return array|null
 */
function pif_normalize(array $f, int $priority): ?array {
    $get = function (array $keys) use ($f): string {
        foreach ($keys as $k) {
            if (isset($f[$k]) && is_scalar($f[$k])) {
                $v = trim((string)$f[$k]);
                if ($v !== '' && $v !== 'null') return $v;
            }
        }
        return '';
    };

    $fp = $get(['FINGERPRINT', 'fingerprint']);
    $manufacturer = $get(['MANUFACTURER', 'manufacturer']);
    $model = $get(['MODEL', 'model']);
    $patch = $get(['SECURITY_PATCH', 'security_patch']);

    $parts = pif_parse_fingerprint($fp);
    if ($parts === null) return null;
    if (strcasecmp($manufacturer, 'Google') !== 0) return null;
    if (strcasecmp($parts['brand'], 'google') !== 0) return null;
    if ($parts['build_type'] !== 'user' || $parts['tags'] !== 'release-keys') return null;
    if (!pif_valid_product($parts['product'])) return null;
    if (!pif_valid_display($model)) return null;
    if (!pif_valid_date($patch)) return null;

    // 可选：设备上市 SDK，OMK 会校验但不会改变已存储格式。
    $sdk = $get(['DEVICE_INITIAL_SDK_INT', 'FIRST_API_LEVEL', 'first_api_level']);
    if ($sdk !== '' && (!ctype_digit($sdk) || (int)$sdk <= 0)) {
        $sdk = '';
    }

    return [
        'model'         => $model,
        'product'       => $parts['product'],
        'manufacturer'  => 'Google',
        'fingerprint'   => $fp,
        'security_patch'=> $patch,
        'sdk'           => $sdk,
        'priority'      => $priority,
    ];
}

/** 解析 .prop 文本为字段数组 */
function pif_parse_prop_text(string $text): array {
    $out = [];
    foreach (preg_split('/\r\n|\r|\n/', $text) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) continue;
        [$k, $v] = explode('=', $line, 2);
        $out[trim($k)] = trim($v);
    }
    return $out;
}

/**
 * 从单个资产内容里提取所有可归一化记录（一个 JSON 或 prop 可能含一条）。
 * @return array<int,array>
 */
function pif_extract_from_asset(string $name, string $content, int $priority): array {
    $out = [];
    $content = trim($content);
    if ($content === '') return $out;

    if (preg_match('/\.json$/i', $name)) {
        $j = json_decode($content, true);
        if (!is_array($j)) return $out;
        // 可能是单个对象、对象数组，或 {profiles:[...]} / 以设备名为键的映射。
        $candidates = [];
        if (isset($j['FINGERPRINT']) || isset($j['fingerprint'])) {
            $candidates[] = $j;
        } elseif (isset($j['profiles']) && is_array($j['profiles'])) {
            $candidates = $j['profiles'];
        } else {
            foreach ($j as $v) {
                if (is_array($v)) $candidates[] = $v;
            }
        }
        foreach ($candidates as $c) {
            if (!is_array($c)) continue;
            $rec = pif_normalize($c, $priority);
            if ($rec !== null) $out[] = $rec;
        }
        return $out;
    }

    if (preg_match('/\.prop$/i', $name)) {
        $rec = pif_normalize(pif_parse_prop_text($content), $priority);
        if ($rec !== null) $out[] = $rec;
    }
    return $out;
}

/**
 * 从一个 PIF 源收集记录。
 * @return array{profiles:array<int,array>,detail:string}
 */
function pif_collect_source(string $name, array $src, string $accel, int $timeout, int $retries): array {
    $repo = (string)($src['repo'] ?? '');
    $assetRe = (string)($src['asset'] ?? '/\.json$/i');
    $priority = (int)($src['priority'] ?? 1);
    if ($repo === '') return ['profiles' => [], 'detail' => '未配置 repo'];

    $rel = gh_latest_release($repo, $accel, $timeout);
    if ($rel === null) return ['profiles' => [], 'detail' => '取最新 release 失败'];
    $tag = $rel['tag'];
    $assets = $rel['assets'];
    if (empty($assets)) return ['profiles' => [], 'detail' => "release {$tag} 无资产"];

    $profiles = [];
    $considered = 0;
    foreach ($assets as $a) {
        if ($considered >= 200) break;
        if (!preg_match($assetRe, $a['name'])) continue;
        $considered++;
        $content = http_get($a['url'], $accel, $timeout, 1);
        if ($content === false) continue;
        foreach (pif_extract_from_asset($a['name'], $content, $priority) as $rec) {
            $profiles[] = $rec;
        }
    }
    $detail = "release {$tag}，扫描 {$considered} 个资产，得到 " . count($profiles) . ' 条';
    return ['profiles' => $profiles, 'detail' => $detail];
}

/**
 * 合并去重：同一 product 取「优先级更高 + 安全补丁更新」的一条；总体按补丁降序、
 * 其次 model 升序，并截断到上限。
 */
function pif_merge(array $profiles, int $maxDevices): array {
    $byProduct = [];
    foreach ($profiles as $p) {
        $prod = $p['product'];
        if (!isset($byProduct[$prod])) {
            $byProduct[$prod] = $p;
            continue;
        }
        $cur = $byProduct[$prod];
        // 先比优先级（小者优），再比补丁日期（大者优）。
        if ($p['priority'] < $cur['priority']
            || ($p['priority'] === $cur['priority'] && strcmp($p['security_patch'], $cur['security_patch']) > 0)) {
            $byProduct[$prod] = $p;
        }
    }
    $merged = array_values($byProduct);
    usort($merged, function ($a, $b) {
        $c = strcmp($b['security_patch'], $a['security_patch']);
        if ($c !== 0) return $c;
        return strcmp($a['model'], $b['model']);
    });
    if ($maxDevices > 0 && count($merged) > $maxDevices) {
        $merged = array_slice($merged, 0, $maxDevices);
    }
    return $merged;
}

/**
 * 生成 OMK 客户端 feed 到磁盘。
 * @return array{catalog:int,detail:array<string,string>}
 */
function pif_write_feed(array $cfg, array $profiles): array {
    $dataDir = rtrim($cfg['pif_dir'] ?? ($cfg['data_dir'] . '/pif'), '/');
    $propDir = $dataDir . '/device_prop';
    @mkdir($propDir, 0755, true);

    $max = (int)($cfg['pif_max_devices'] ?? 64);
    $merged = pif_merge($profiles, $max);

    // 清理旧的 prop 文件（保留当前这批 product）：避免旧设备残留导致目录无限增长。
    $keep = [];
    foreach ($merged as $p) {
        $keep[$p['product'] . '.prop'] = true;
    }
    foreach (glob($propDir . '/*.prop') ?: [] as $f) {
        if (!isset($keep[basename($f)])) @unlink($f);
    }

    $catalog = [];
    foreach ($merged as $p) {
        $catalog[] = ['model' => $p['model'], 'product' => $p['product']];

        $lines = [
            'FINGERPRINT=' . $p['fingerprint'],
            'MANUFACTURER=Google',
            'MODEL=' . $p['model'],
            'SECURITY_PATCH=' . $p['security_patch'],
        ];
        if ($p['sdk'] !== '') {
            $lines[] = 'DEVICE_INITIAL_SDK_INT=' . $p['sdk'];
        }
        @file_put_contents($propDir . '/' . $p['product'] . '.prop', implode("\n", $lines) . "\n");
    }

    // 目录按 model 排序，稳定输出。
    usort($catalog, function ($a, $b) {
        $c = strcmp($a['model'], $b['model']);
        return $c !== 0 ? $c : strcmp($a['product'], $b['product']);
    });
    @file_put_contents(
        $dataDir . '/device_list.json',
        json_encode($catalog, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
    );

    return [
        'catalog' => count($catalog),
        'detail'  => [],
    ];
}
