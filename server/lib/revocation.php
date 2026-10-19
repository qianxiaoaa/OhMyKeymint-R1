<?php
/**
 * 吊销名单 —— 多源合并、可信度分级、客户端证据上报、永久吊销名单。
 *
 * 三类数据，职责严格分开：
 *
 *   1. 在线快照 data/revocation.json
 *      每轮从 config.revocation_sources 并行拉取。**所有成功源合并**，不再
 *      「取第一个成功源就返回」——旧实现只要第一个源能下就丢掉其它渠道，
 *      导致某些渠道早已收录的序列号在本服务器上不可见。
 *
 *   2. 永久名单 data/revoked_permanent.json（append-only）
 *      只增不删。写入来源只有两种：
 *        - 在线命中且满足可信条件（可信源命中，或 ≥2 个独立源同时命中）；
 *        - 客户端上报达到独立设备阈值。
 *      轮换池入池前与每次下发前都以它为最终拦截依据，避免「今天判定吊销、
 *      明天缓存里没有又把同一份 keybox 发出去」。
 *
 *   3. 客户端上报聚合 data/revocation_reports.json
 *      客户端只上报 证书序列号 + keybox SHA-256 + 来源 + 检测时间。
 *      上报者身份用 IP 加盐哈希做去重，不落盘 IP、不采集应用数据。
 *
 * 序列号一律使用 serial.php 的规范十六进制（大写、整字节、去前导零字节），
 * 与 keybox.php / kb_normalize_revoked() 的格式完全一致。
 */

require_once __DIR__ . '/serial.php';
require_once __DIR__ . '/http.php';

/* ------------------------------------------------------------------ */
/* 名单解析                                                            */
/* ------------------------------------------------------------------ */

if (!function_exists('rev_parse')) {
    /**
     * 解析一份 status JSON，返回以规范十六进制为键的索引。
     *
     * @param string $json
     * @param string $source 来源名（写入每个条目的 sources）
     * @return array<string,array{status:string,reason:string,dec:string,sources:array<int,string>}>
     */
    function rev_parse(string $json, string $source = ''): array
    {
        $j = json_decode($json, true);
        if (!is_array($j) || !isset($j['entries']) || !is_array($j['entries'])) {
            return [];
        }
        $out = [];
        foreach ($j['entries'] as $serial => $info) {
            $serial = trim((string)$serial);
            if ($serial === '') {
                continue;
            }
            $isDec = ctype_digit($serial);
            $hex = $isDec ? omk_dec_to_hex($serial) : omk_norm_serial_hex($serial);
            if ($hex === '' || $hex === '0') {
                continue;
            }
            $status = is_array($info) ? (string)($info['status'] ?? 'REVOKED') : 'REVOKED';
            $reason = is_array($info) ? (string)($info['reason'] ?? '') : '';
            if (!isset($out[$hex])) {
                $out[$hex] = [
                    'status'  => $status,
                    'reason'  => $reason,
                    'dec'     => $isDec ? $serial : '',
                    'sources' => [],
                ];
            }
            if ($source !== '' && !in_array($source, $out[$hex]['sources'], true)) {
                $out[$hex]['sources'][] = $source;
            }
        }
        return $out;
    }
}

if (!function_exists('rev_merge_entries')) {
    /**
     * 合并多份解析结果：序列号取并集，来源与原因累积。
     *
     * @param array<int,array> $parts 每项是 rev_parse() 的返回值
     * @param array<int,string> $trusted 可信来源名
     * @return array<string,array>
     */
    function rev_merge_entries(array $parts, array $trusted = []): array
    {
        $merged = [];
        foreach ($parts as $entries) {
            foreach ($entries as $hex => $e) {
                $hex = omk_norm_serial_hex((string)$hex);
                if ($hex === '' || $hex === '0') {
                    continue;
                }
                if (!isset($merged[$hex])) {
                    $merged[$hex] = [
                        'status'  => (string)($e['status'] ?? 'REVOKED'),
                        'reason'  => (string)($e['reason'] ?? ''),
                        'dec'     => (string)($e['dec'] ?? ''),
                        'sources' => [],
                    ];
                }
                foreach (($e['sources'] ?? []) as $s) {
                    if ($s !== '' && !in_array($s, $merged[$hex]['sources'], true)) {
                        $merged[$hex]['sources'][] = $s;
                    }
                }
                if ($merged[$hex]['reason'] === '' && !empty($e['reason'])) {
                    $merged[$hex]['reason'] = (string)$e['reason'];
                }
                if ($merged[$hex]['dec'] === '' && !empty($e['dec'])) {
                    $merged[$hex]['dec'] = (string)$e['dec'];
                }
            }
        }

        foreach ($merged as $hex => $e) {
            $trustedHit = false;
            foreach ($e['sources'] as $s) {
                if (in_array($s, $trusted, true)) {
                    $trustedHit = true;
                    break;
                }
            }
            if ($trustedHit) {
                $merged[$hex]['confidence'] = 'confirmed';
            } elseif (count($e['sources']) >= 2) {
                $merged[$hex]['confidence'] = 'corroborated';
            } else {
                $merged[$hex]['confidence'] = 'single';
            }
        }
        return $merged;
    }
}

if (!function_exists('rev_load')) {
    /**
     * 读取在线快照缓存。兼容旧格式（小写、未补字节的键）。
     *
     * @return array{fetched_at:int,sources:array,entries:array,per_source:array}|null
     */
    function rev_load(string $cacheFile): ?array
    {
        if (!is_file($cacheFile)) {
            return null;
        }
        $j = json_decode((string)@file_get_contents($cacheFile), true);
        if (!is_array($j) || empty($j['entries']) || !is_array($j['entries'])) {
            return null;
        }

        $entries = [];
        foreach ($j['entries'] as $hex => $e) {
            $hex = omk_norm_serial_hex((string)$hex);
            if ($hex === '' || $hex === '0' || !is_array($e)) {
                continue;
            }
            $srcs = $e['sources'] ?? [];
            if (!is_array($srcs)) {
                $srcs = [];
            }
            if (empty($srcs) && !empty($j['source'])) {
                $srcs[] = (string)$j['source'];
            }
            $entries[$hex] = [
                'status'  => (string)($e['status'] ?? 'REVOKED'),
                'reason'  => (string)($e['reason'] ?? ''),
                'dec'     => (string)($e['dec'] ?? ''),
                'sources' => array_values(array_unique(array_map('strval', $srcs))),
                'confidence' => (string)($e['confidence'] ?? 'single'),
            ];
        }
        if (empty($entries)) {
            return null;
        }

        return [
            'fetched_at' => (int)($j['fetched_at'] ?? 0),
            'sources'    => is_array($j['sources'] ?? null) ? $j['sources'] : (array)($j['source'] ?? []),
            'per_source' => is_array($j['per_source'] ?? null) ? $j['per_source'] : [],
            'entries'    => $entries,
        ];
    }
}

if (!function_exists('rev_write_atomic')) {
    /** 先写临时文件再 rename，避免并发读到半截 JSON。 */
    function rev_write_atomic(string $file, array $payload): bool
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $tmp = $file . '.tmp.' . getmypid() . '.' . bin2hex(random_bytes(4));
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false || @file_put_contents($tmp, $json) === false) {
            return false;
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }
}

if (!function_exists('rev_mutate_json')) {
    /**
     * 在文件锁内读改写 JSON。上报与永久名单都是「读-改-写」，并发请求下
     * 无锁会丢更新（两个设备同时上报时阈值可能永远差一条）。
     *
     * @param callable $fn 接收当前数组，返回新数组
     */
    function rev_mutate_json(string $file, callable $fn, array $default = []): array
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            $out = $fn($default);
            return is_array($out) ? $out : $default;
        }
        if (!@flock($fp, LOCK_EX)) {
            @fclose($fp);
            return $default;
        }
        $raw = stream_get_contents($fp);
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            $data = $default;
        }
        $out = $fn($data);
        if (!is_array($out)) {
            $out = $data;
        }
        @ftruncate($fp, 0);
        @rewind($fp);
        @fwrite($fp, json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        @fflush($fp);
        @flock($fp, LOCK_UN);
        @fclose($fp);
        return $out;
    }
}

/* ------------------------------------------------------------------ */
/* 多源并行下载                                                        */
/* ------------------------------------------------------------------ */

if (!function_exists('rev_http_multi')) {
    /**
     * 并行 GET，一次把多个源全部拉下来。
     * @param array<string,string> $urls key => URL
     * @return array<string,string> key => body（失败的不出现）
     */
    function rev_http_multi(array $urls, int $timeout, bool $verifyTls = true): array
    {
        if (empty($urls) || !function_exists('curl_multi_init')) {
            return [];
        }
        $mh = curl_multi_init();
        $handles = [];
        foreach ($urls as $key => $url) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 5,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_CONNECTTIMEOUT => min(10, $timeout),
                CURLOPT_SSL_VERIFYPEER => $verifyTls,
                CURLOPT_SSL_VERIFYHOST => $verifyTls ? 2 : 0,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (OhMyKeymint-server)',
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$key] = $ch;
        }

        $running = 0;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running > 0) {
                curl_multi_select($mh, 1.0);
            }
        } while ($running > 0 && $status === CURLM_OK);

        $out = [];
        foreach ($handles as $key => $ch) {
            $body = curl_multi_getcontent($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if ($code >= 200 && $code < 300 && is_string($body) && $body !== '') {
                $out[$key] = $body;
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);
        return $out;
    }
}

/**
 * 多源拉取吊销名单（带缓存）。
 *
 * @param array       $sources    ['名字' => 'URL', ...]
 * @param string      $accel      GitHub 加速前缀
 * @param string      $cacheFile  缓存文件路径
 * @param int         $timeout    单次超时秒
 * @param int         $maxAge     缓存新鲜度（秒）
 * @param bool        $verifyTls  TLS 校验
 * @param array       $trusted    可信来源名（命中即 confirmed）
 * @return array{entries:array,source:string,sources:array,fetched_at:int,fresh:bool,tried:array,per_source:array}
 */
function rev_fetch(array $sources, string $accel, string $cacheFile, int $timeout = 20,
                   int $maxAge = 86400, bool $verifyTls = true, array $trusted = []): array
{
    $cached = rev_load($cacheFile);
    if ($cached !== null && (time() - (int)($cached['fetched_at'] ?? 0)) < $maxAge) {
        return [
            'entries'    => $cached['entries'],
            'source'     => implode('+', array_map('strval', (array)$cached['sources'])) . '(缓存)',
            'sources'    => (array)$cached['sources'],
            'fetched_at' => (int)($cached['fetched_at'] ?? 0),
            'fresh'      => true,
            'tried'      => [],
            'per_source' => (array)$cached['per_source'],
        ];
    }

    // 第一轮：全部源并行（GitHub 源走加速前缀）。
    $targets = [];
    foreach ($sources as $name => $url) {
        $url = trim((string)$url);
        if ($url === '') {
            continue;
        }
        $isGithub = (strpos($url, 'github.com') !== false)
            || (strpos($url, 'raw.githubusercontent.com') !== false);
        $targets[(string)$name] = ($isGithub && $accel !== '' && strpos($url, $accel) !== 0)
            ? rtrim($accel, '/') . '/' . ltrim($url, '/')
            : $url;
    }
    $bodies = rev_http_multi($targets, $timeout, $verifyTls);

    // 第二轮：并行失败的逐个重试。已经有源成功时，失败源只给一次短超时机会，
    // 避免一个连不通的官方地址把整轮更新拖到几分钟。
    $haveSuccess = !empty($bodies);
    $retryTimeout = $haveSuccess ? min(10, max(3, $timeout)) : $timeout;
    $retryTimes = $haveSuccess ? 1 : 2;

    $tried = [];
    $perSource = [];
    $parts = [];
    $okSources = [];
    foreach ($sources as $name => $url) {
        $name = (string)$name;
        $body = $bodies[$name] ?? false;
        if ($body === false) {
            $body = http_get((string)$url, $accel, $retryTimeout, $retryTimes, $verifyTls);
        }
        if ($body === false) {
            $perSource[$name] = ['ok' => false, 'count' => 0, 'why' => '下载失败'];
            $tried[] = $name . ': 下载失败';
            continue;
        }
        $entries = rev_parse($body, $name);
        // 残缺响应（错误页 / 限流页）跳过：真实名单有几百条。
        if (count($entries) < 50) {
            $perSource[$name] = ['ok' => false, 'count' => count($entries), 'why' => '条数异常'];
            $tried[] = $name . ': 只解析出 ' . count($entries) . ' 条，判定不完整，跳过';
            continue;
        }
        $parts[] = $entries;
        $okSources[] = $name;
        $perSource[$name] = ['ok' => true, 'count' => count($entries), 'why' => ''];
    }

    if (!empty($parts)) {
        $entries = rev_merge_entries($parts, $trusted);
        $payload = [
            'version'    => 2,
            'fetched_at' => time(),
            'sources'    => $okSources,
            'count'      => count($entries),
            'per_source' => $perSource,
            'entries'    => $entries,
        ];
        rev_write_atomic($cacheFile, $payload);
        return [
            'entries'    => $entries,
            'source'     => implode('+', $okSources),
            'sources'    => $okSources,
            'fetched_at' => time(),
            'fresh'      => true,
            'tried'      => $tried,
            'per_source' => $perSource,
        ];
    }

    // 全部源失败：过期缓存也比没有强（吊销名单变化很慢）。
    if ($cached !== null) {
        return [
            'entries'    => $cached['entries'],
            'source'     => implode('+', array_map('strval', (array)$cached['sources'])) . '(已过期缓存)',
            'sources'    => (array)$cached['sources'],
            'fetched_at' => (int)($cached['fetched_at'] ?? 0),
            'fresh'      => false,
            'tried'      => $tried,
            'per_source' => $perSource,
        ];
    }
    return [
        'entries' => [], 'source' => '(全部源不可用)', 'sources' => [], 'fetched_at' => 0,
        'fresh' => false, 'tried' => $tried, 'per_source' => $perSource,
    ];
}

/* ------------------------------------------------------------------ */
/* 查询工具                                                            */
/* ------------------------------------------------------------------ */

if (!function_exists('rev_to_revoked_list')) {
    /**
     * 十六进制键列表 -> kb_normalize_revoked() 能吃的形式。
     * 必须加 0x 前缀：否则纯数字的十六进制串会被误判成十进制再转一次。
     */
    function rev_to_revoked_list(array $entries): array
    {
        $out = [];
        foreach (array_keys($entries) as $hex) {
            $hex = omk_norm_serial_hex((string)$hex);
            if ($hex === '' || $hex === '0') {
                continue;
            }
            $out[] = '0x' . $hex;
        }
        return $out;
    }
}

if (!function_exists('rev_check')) {
    /**
     * 在名单里查一组序列号。
     *
     * 传入值按【十六进制】解释：调用方都来自证书解析（kb_extract_certs），
     * 写成纯十进制会被误转一次，所以这里不做十进制猜测。外部数据要按十进制
     * 查询时先用 omk_dec_to_hex() 转换。
     *
     * @return array [hex => 命中信息]
     */
    function rev_check(array $entries, array $serials): array
    {
        $hit = [];
        foreach ($serials as $s) {
            $hex = omk_norm_serial_hex((string)$s);
            if ($hex !== '' && $hex !== '0' && isset($entries[$hex])) {
                $hit[$hex] = $entries[$hex];
            }
        }
        return $hit;
    }
}

/* ------------------------------------------------------------------ */
/* 永久吊销名单                                                        */
/* ------------------------------------------------------------------ */

if (!function_exists('rev_permanent_path')) {
    function rev_permanent_path(array $cfg): string
    {
        return rtrim((string)$cfg['data_dir'], '/') . '/revoked_permanent.json';
    }
}

if (!function_exists('rev_permanent_load')) {
    /**
     * @return array{version:int,updated_at:string,entries:array}
     */
    function rev_permanent_load(array $cfg): array
    {
        $file = rev_permanent_path($cfg);
        $empty = ['version' => 0, 'updated_at' => '', 'entries' => []];
        if (!is_file($file)) {
            return $empty;
        }
        $j = json_decode((string)@file_get_contents($file), true);
        if (!is_array($j) || !isset($j['entries']) || !is_array($j['entries'])) {
            return $empty;
        }
        $entries = [];
        foreach ($j['entries'] as $hex => $e) {
            $hex = omk_norm_serial_hex((string)$hex);
            if ($hex === '' || $hex === '0' || !is_array($e)) {
                continue;
            }
            $entries[$hex] = $e;
        }
        return [
            'version'    => (int)($j['version'] ?? count($entries)),
            'updated_at' => (string)($j['updated_at'] ?? ''),
            'entries'    => $entries,
        ];
    }
}

if (!function_exists('rev_permanent_add')) {
    /**
     * 把一个序列号加入永久名单（已存在则累积来源，不重复计数）。
     *
     * @return array{added:bool,changed:bool}
     */
    function rev_permanent_add(array &$data, string $hex, array $meta): array
    {
        $hex = omk_norm_serial_hex($hex);
        if ($hex === '' || $hex === '0') {
            return ['added' => false, 'changed' => false];
        }
        $now = time();
        $e = $data['entries'][$hex] ?? null;
        if ($e === null) {
            $data['entries'][$hex] = [
                'serial'     => '0x' . $hex,
                'status'     => (string)($meta['status'] ?? 'REVOKED'),
                'reason'     => (string)($meta['reason'] ?? ''),
                'sources'    => array_values(array_unique(array_map('strval', (array)($meta['sources'] ?? [])))),
                'confidence' => (string)($meta['confidence'] ?? 'single'),
                'reports'    => (int)($meta['reports'] ?? 0),
                'distinct_reporters' => (int)($meta['distinct_reporters'] ?? 0),
                'first_seen' => $now,
                'last_seen'  => $now,
            ];
            return ['added' => true, 'changed' => true];
        }

        $changed = false;
        foreach (($meta['sources'] ?? []) as $s) {
            $s = (string)$s;
            if ($s !== '' && !in_array($s, $e['sources'] ?? [], true)) {
                $e['sources'][] = $s;
                $changed = true;
            }
        }
        if ((int)($e['reports'] ?? 0) < (int)($meta['reports'] ?? 0)) {
            $e['reports'] = (int)$meta['reports'];
            $changed = true;
        }
        if ((int)($e['distinct_reporters'] ?? 0) < (int)($meta['distinct_reporters'] ?? 0)) {
            $e['distinct_reporters'] = (int)$meta['distinct_reporters'];
            $changed = true;
        }
        $rank = ['single' => 0, 'corroborated' => 1, 'client_confirmed' => 2, 'confirmed' => 3];
        $newConf = (string)($meta['confidence'] ?? 'single');
        if (($rank[$newConf] ?? 0) > ($rank[(string)($e['confidence'] ?? 'single')] ?? 0)) {
            $e['confidence'] = $newConf;
            $changed = true;
        }
        if ($e['reason'] === '' && !empty($meta['reason'])) {
            $e['reason'] = (string)$meta['reason'];
            $changed = true;
        }
        $e['last_seen'] = $now;
        $data['entries'][$hex] = $e;
        return ['added' => false, 'changed' => $changed];
    }
}

if (!function_exists('rev_permanent_sync_online')) {
    /**
     * 把在线快照中满足可信条件的条目并入永久名单。
     *
     * @return array{added:int,updated:int,version:int,count:int}
     */
    function rev_permanent_sync_online(array $cfg, array $entries): array
    {
        $added = 0;
        $data = rev_mutate_json(rev_permanent_path($cfg), function (array $data) use ($entries, &$added): array {
            $changed = false;
            foreach ($entries as $hex => $e) {
                $conf = (string)($e['confidence'] ?? 'single');
                if ($conf !== 'confirmed' && $conf !== 'corroborated') {
                    continue;
                }
                $r = rev_permanent_add($data, (string)$hex, [
                    'status'     => $e['status'] ?? 'REVOKED',
                    'reason'     => $e['reason'] ?? '',
                    'sources'    => $e['sources'] ?? [],
                    'confidence' => $conf,
                ]);
                if ($r['added']) {
                    $added++;
                    $changed = true;
                } elseif ($r['changed']) {
                    $changed = true;
                }
            }
            if ($changed) {
                $data['version'] = (int)($data['version'] ?? 0) + 1;
                $data['updated_at'] = date('Y-m-d H:i:s');
            }
            return $data;
        }, ['version' => 0, 'updated_at' => '', 'entries' => []]);

        return [
            'added'   => $added,
            'updated' => $added > 0 ? 1 : 0,
            'version' => (int)($data['version'] ?? 0),
            'count'   => count($data['entries'] ?? []),
        ];
    }
}

if (!function_exists('rev_permanent_hits')) {
    /** 返回给定序列号中命中永久名单的部分。 */
    function rev_permanent_hits(array $cfg, array $serials): array
    {
        $perm = rev_permanent_load($cfg);
        return rev_check($perm['entries'], $serials);
    }
}

if (!function_exists('rev_blacklist_serials')) {
    /**
     * 最终拦截名单 = 手工列表 + 永久名单 + 在线快照。
     * 返回 ["0x..."...]，可直接交给 kb_normalize_revoked()。
     *
     * @param array|null $onlineEntries 传入本轮刚拉到的快照可省一次读文件
     */
    function rev_blacklist_serials(array $cfg, ?array $onlineEntries = null): array
    {
        $out = (array)($cfg['revoked_serials'] ?? []);

        $perm = rev_permanent_load($cfg);
        $out = array_merge($out, rev_to_revoked_list($perm['entries']));

        if ($onlineEntries === null) {
            $cached = rev_load(rtrim((string)$cfg['data_dir'], '/') . '/revocation.json');
            $onlineEntries = $cached['entries'] ?? [];
        }
        $out = array_merge($out, rev_to_revoked_list($onlineEntries));

        return array_values(array_unique(array_map('strval', $out)));
    }
}

/* ------------------------------------------------------------------ */
/* 客户端上报                                                          */
/* ------------------------------------------------------------------ */

if (!function_exists('rev_reports_path')) {
    function rev_reports_path(array $cfg): string
    {
        return rtrim((string)$cfg['data_dir'], '/') . '/revocation_reports.json';
    }
}

if (!function_exists('rev_reports_load')) {
    function rev_reports_load(array $cfg): array
    {
        $file = rev_reports_path($cfg);
        $empty = ['updated_at' => '', 'serials' => []];
        if (!is_file($file)) {
            return $empty;
        }
        $j = json_decode((string)@file_get_contents($file), true);
        if (!is_array($j) || !isset($j['serials']) || !is_array($j['serials'])) {
            return $empty;
        }
        return ['updated_at' => (string)($j['updated_at'] ?? ''), 'serials' => $j['serials']];
    }
}

if (!function_exists('rev_report_salt')) {
    /** 去重盐：首次使用时生成，只落盘在私有 data 目录。 */
    function rev_report_salt(array $cfg): string
    {
        $file = rtrim((string)$cfg['data_dir'], '/') . '/report_salt';
        if (is_file($file)) {
            $s = trim((string)@file_get_contents($file));
            if (strlen($s) >= 32) {
                return $s;
            }
        }
        $s = bin2hex(random_bytes(32));
        @file_put_contents($file, $s);
        @chmod($file, 0600);
        return $s;
    }
}

if (!function_exists('rev_reporter_id')) {
    /**
     * 上报者标识：IP 加盐哈希，只用于「两个独立设备」计数。
     * 不落盘 IP，不可逆。
     */
    function rev_reporter_id(array $cfg): string
    {
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        if ($ip === '') {
            $ip = 'unknown';
        }
        return substr(hash_hmac('sha256', $ip, rev_report_salt($cfg)), 0, 32);
    }
}

if (!function_exists('rev_report_rate_limit')) {
    /**
     * 滑动窗口限流，防止单设备刷上报。
     * @return bool true=允许
     */
    function rev_report_rate_limit(array $cfg, string $reporter, int $limit, int $window): bool
    {
        $file = rtrim((string)$cfg['data_dir'], '/') . '/report_rate.json';
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return true; // 限流设施不可用时不阻塞正常上报
        }
        if (!@flock($fp, LOCK_EX)) {
            @fclose($fp);
            return true;
        }
        $raw = stream_get_contents($fp);
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            $data = [];
        }
        $now = time();
        $hits = [];
        foreach ((array)($data[$reporter] ?? []) as $ts) {
            $ts = (int)$ts;
            if ($now - $ts < $window) {
                $hits[] = $ts;
            }
        }
        $allow = count($hits) < $limit;
        if ($allow) {
            $hits[] = $now;
        }
        $data[$reporter] = $hits;
        // 清理窗口外的上报者，避免文件无限增长。
        if (count($data) > 5000) {
            foreach ($data as $k => $v) {
                if (!is_array($v) || empty($v) || $now - (int)max($v) >= $window) {
                    unset($data[$k]);
                }
            }
        }
        @ftruncate($fp, 0);
        @rewind($fp);
        @fwrite($fp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        @fflush($fp);
        @flock($fp, LOCK_UN);
        @fclose($fp);
        return $allow;
    }
}

if (!function_exists('rev_report_validate')) {
    /**
     * 校验客户端上报字段。只接受最小集合，任何多余字段一律忽略。
     *
     * @param array $in 原始输入（GET 或 JSON POST 解析结果）
     * @return array{ok:bool,why:string,report:array}
     */
    function rev_report_validate(array $in): array
    {
        $serial = $in['serial'] ?? ($in['serial_hex'] ?? '');
        if (!is_string($serial)) {
            return ['ok' => false, 'why' => 'serial 必须是字符串', 'report' => []];
        }
        $serial = trim($serial);
        if ($serial === '' || strlen($serial) > 96 || !preg_match('/^(0[xX])?[0-9A-Fa-f:\-\s]+$/', $serial)) {
            return ['ok' => false, 'why' => 'serial 格式非法', 'report' => []];
        }
        // 客户端上报的序列号来自证书，默认按十六进制解释；只有明确给出
        // 十进制时间戳式序列号（纯数字且不带 0x / serial_hex）才按十进制转。
        $explicitHex = isset($in['serial_hex']) || str_starts_with(strtolower($serial), '0x');
        $hex = $explicitHex ? omk_norm_serial_hex(preg_replace('/^0[xX]/', '', $serial)) : omk_serial_to_hex($serial);
        if ($hex === '' || $hex === '0' || strlen($hex) > 80) {
            return ['ok' => false, 'why' => 'serial 无法规范化', 'report' => []];
        }

        $sha = $in['keybox_sha256'] ?? ($in['sha256'] ?? '');
        if (!is_string($sha) || !preg_match('/^[0-9a-fA-F]{64}$/', trim($sha))) {
            return ['ok' => false, 'why' => 'keybox_sha256 必须是 64 位十六进制', 'report' => []];
        }
        $sha = strtolower(trim($sha));

        $source = $in['source'] ?? 'unknown';
        if (!is_string($source)) {
            $source = 'unknown';
        }
        $source = substr(preg_replace('/[^A-Za-z0-9._\-\/]/', '', $source) ?? '', 0, 64);
        if ($source === '') {
            $source = 'unknown';
        }

        $reason = $in['reason'] ?? '';
        if (!is_string($reason)) {
            $reason = '';
        }
        $reason = substr(preg_replace('/[^A-Za-z0-9._\-]/', '', $reason) ?? '', 0, 64);

        $detected = $in['detected_at'] ?? 0;
        if (is_string($detected) && !ctype_digit($detected)) {
            $t = strtotime($detected);
            $detected = ($t === false) ? 0 : $t;
        } else {
            $detected = (int)$detected;
        }
        $now = time();
        if ($detected <= 0 || $detected > $now + 86400) {
            $detected = $now;
        }

        return ['ok' => true, 'why' => '', 'report' => [
            'hex'          => $hex,
            'serial'       => '0x' . $hex,
            'keybox_sha256'=> $sha,
            'source'       => $source,
            'reason'       => $reason,
            'detected_at'  => $detected,
        ]];
    }
}

if (!function_exists('rev_report_ingest')) {
    /**
     * 收下一条客户端上报；达到独立设备阈值时自动入永久名单。
     *
     * @return array{accepted:bool,promoted:bool,pending:bool,version:int,count:int,why:string}
     */
    function rev_report_ingest(array $cfg, array $in, ?string $reporter = null): array
    {
        $limit = max(1, (int)($cfg['report_rate_limit'] ?? 20));
        $window = max(60, (int)($cfg['report_rate_window'] ?? 3600));
        $reporter = $reporter ?? rev_reporter_id($cfg);
        if (!rev_report_rate_limit($cfg, $reporter, $limit, $window)) {
            return ['accepted' => false, 'promoted' => false, 'pending' => false,
                    'version' => rev_permanent_load($cfg)['version'], 'count' => 0, 'why' => 'rate limited'];
        }

        $v = rev_report_validate($in);
        if (!$v['ok']) {
            return ['accepted' => false, 'promoted' => false, 'pending' => false,
                    'version' => rev_permanent_load($cfg)['version'], 'count' => 0, 'why' => $v['why']];
        }
        $r = $v['report'];
        $hex = $r['hex'];
        $threshold = max(1, (int)($cfg['report_threshold'] ?? 2));

        $reports = rev_mutate_json(rev_reports_path($cfg), function (array $data) use ($r, $hex, $reporter): array {
            if (!isset($data['serials']) || !is_array($data['serials'])) {
                $data['serials'] = [];
            }
            $now = time();
            $entry = $data['serials'][$hex] ?? null;
            if (!is_array($entry)) {
                $entry = [
                    'serial'        => $r['serial'],
                    'reporters'     => [],
                    'sources'       => [],
                    'keybox_sha256' => [],
                    'reasons'       => [],
                    'first_seen'    => $now,
                    'last_seen'     => $now,
                    'promoted'      => false,
                ];
            }
            if (!isset($entry['reporters']) || !is_array($entry['reporters'])) {
                $entry['reporters'] = [];
            }
            $entry['reporters'][$reporter] = $now;
            $entry['last_seen'] = $now;
            if (!in_array($r['source'], $entry['sources'] ?? [], true)) {
                $entry['sources'][] = $r['source'];
            }
            if (!in_array($r['keybox_sha256'], $entry['keybox_sha256'] ?? [], true)) {
                $entry['keybox_sha256'][] = $r['keybox_sha256'];
                $entry['keybox_sha256'] = array_slice($entry['keybox_sha256'], -5);
            }
            if ($r['reason'] !== '' && !in_array($r['reason'], $entry['reasons'] ?? [], true)) {
                $entry['reasons'][] = $r['reason'];
            }
            $data['serials'][$hex] = $entry;
            $data['updated_at'] = date('Y-m-d H:i:s');
            return $data;
        }, ['updated_at' => '', 'serials' => []]);

        $entry = $reports['serials'][$hex];
        $distinct = count($entry['reporters']);
        $promoted = false;
        if ($distinct >= $threshold && empty($entry['promoted'])) {
            rev_mutate_json(rev_permanent_path($cfg), function (array $data) use ($hex, $entry, $distinct): array {
                $res = rev_permanent_add($data, $hex, [
                    'status'             => 'REVOKED',
                    'reason'             => $entry['reasons'][0] ?? '',
                    'sources'            => array_map(fn($s) => 'client:' . $s, $entry['sources'] ?? []),
                    'confidence'         => 'client_confirmed',
                    'reports'            => $distinct,
                    'distinct_reporters' => $distinct,
                ]);
                if ($res['added'] || $res['changed']) {
                    $data['version'] = (int)($data['version'] ?? 0) + 1;
                    $data['updated_at'] = date('Y-m-d H:i:s');
                }
                return $data;
            }, ['version' => 0, 'updated_at' => '', 'entries' => []]);

            $reports = rev_mutate_json(rev_reports_path($cfg), function (array $data) use ($hex): array {
                if (isset($data['serials'][$hex]) && is_array($data['serials'][$hex])) {
                    $data['serials'][$hex]['promoted'] = true;
                    $data['updated_at'] = date('Y-m-d H:i:s');
                }
                return $data;
            }, ['updated_at' => '', 'serials' => []]);

            $permCheck = rev_permanent_load($cfg);
            $promoted = isset($permCheck['entries'][$hex]);
        }

        $perm = rev_permanent_load($cfg);
        return [
            'accepted' => true,
            'promoted' => $promoted,
            'pending'  => !isset($perm['entries'][$hex]),
            'version'  => (int)$perm['version'],
            'count'    => count($perm['entries']),
            'why'      => '',
        ];
    }
}

if (!function_exists('rev_status')) {
    /** manifest 用的吊销状态摘要（不包含具体序列号，避免清单膨胀）。 */
    function rev_status(array $cfg): array
    {
        $perm = rev_permanent_load($cfg);
        $reports = rev_reports_load($cfg);
        $cacheFile = rtrim((string)$cfg['data_dir'], '/') . '/revocation.json';
        $cache = rev_load($cacheFile);

        $pending = 0;
        foreach ($reports['serials'] as $e) {
            if (empty($e['promoted'])) {
                $pending++;
            }
        }

        $sources = [];
        if ($cache !== null) {
            foreach ((array)$cache['per_source'] as $name => $info) {
                $sources[] = [
                    'source' => (string)$name,
                    'ok'     => !empty($info['ok']),
                    'count'  => (int)($info['count'] ?? 0),
                    'why'    => (string)($info['why'] ?? ''),
                ];
            }
        }

        return [
            'version'         => (int)$perm['version'],
            'permanent_count' => count($perm['entries']),
            'updated_at'      => (string)$perm['updated_at'],
            'report_count'    => count($reports['serials']),
            'pending_count'   => $pending,
            'cache_fetched_at'=> (int)($cache['fetched_at'] ?? 0),
            'cache_count'     => $cache === null ? 0 : count($cache['entries']),
            'sources'         => $sources,
        ];
    }
}
