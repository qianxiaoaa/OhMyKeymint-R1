<?php
/**
 * keybox 解码与目录取样。
 * HTTP 下载实现统一在 lib/http.php（加速、重试、TLS 校验、目录列表缓存）。
 */

declare(strict_types=1);

require_once __DIR__ . '/http.php';

/** 去除空白字符（空格 / 换行 / 回车 / tab） */
function strip_ws(string $s): string {
    return preg_replace('/\s+/', '', $s);
}

/**
 * 按类型解码 keybox 原始内容。
 * @return string|false
 */
function decode_keybox(string $raw, string $type) {
    // 只去掉真正的换行与制表符：空格要保留（hex_base64 的中间层可能解出
    // 带空格分组的 hex 串，剥掉空格会让 hex2bin 失败）。
    $raw = preg_replace('/[\r\n\t]+/', '', $raw);
    if ($raw === '') {
        return false;
    }
    switch ($type) {
        case 'base64': {
            $d = base64_decode($raw, true);
            return ($d === false || $d === '') ? false : $d;
        }
        case 'hex_base64': {
            $hex = preg_replace('/\s+/', '', $raw);
            if (strlen($hex) % 2 !== 0) return false;
            $h = @hex2bin($hex);
            if ($h === false) return false;
            if (strpos($h, '<?xml') !== false || strpos($h, '<AndroidAttestation>') !== false) {
                return $h;
            }
            $d = base64_decode(preg_replace('/\s+/', '', $h), true);
            if ($d !== false && $d !== '' && (strpos($d, '<?xml') !== false || strpos($d, '<AndroidAttestation>') !== false)) {
                return $d;
            }
            return $h;
        }
        case 'multi_base64_hex_rot13': {
            $d = $raw;
            for ($i = 0; $i < 10; $i++) {
                $d = preg_replace('/\s+/', '', $d);
                if ($d === '') return false;
                $dec = base64_decode($d, true);
                if ($dec === false || $dec === '') return false;
                $d = $dec;
            }
            $d = preg_replace('/\s+/', '', $d);
            if (strlen($d) % 2 !== 0) return false;
            $h = @hex2bin($d);
            if ($h === false) return false;
            $out = str_rot13($h);
            return ($out === '' || $out === false) ? false : $out;
        }
        default:
            return false;
    }
}

/**
 * 把可能带 BOM / UTF-16 的文本统一成 UTF-8。
 * shall0e/KeyboxHub 里的 keybox 文件是 UTF-16LE 带 BOM 存的。
 */
function kb_to_utf8(string $s): string {
    if (strncmp($s, "\xFF\xFE", 2) === 0) {
        $s = substr($s, 2);
        $enc = 'UTF-16LE';
    } elseif (strncmp($s, "\xFE\xFF", 2) === 0) {
        $s = substr($s, 2);
        $enc = 'UTF-16BE';
    } elseif (strncmp($s, "\xEF\xBB\xBF", 3) === 0) {
        return substr($s, 3);
    } else {
        return $s;
    }
    if (function_exists('mb_convert_encoding')) {
        return mb_convert_encoding($s, 'UTF-8', $enc);
    }
    if (function_exists('iconv')) {
        $r = @iconv($enc, 'UTF-8//IGNORE', $s);
        if ($r !== false) return $r;
    }
    $out = '';
    $n = strlen($s) - 1;
    for ($i = 0; $i < $n; $i += 2) {
        $cp = ($enc === 'UTF-16LE')
            ? (ord($s[$i]) | (ord($s[$i + 1]) << 8))
            : ((ord($s[$i]) << 8) | ord($s[$i + 1]));
        if ($cp === 0) continue;
        $out .= ($cp < 0x80) ? chr($cp) : '?';
    }
    return $out;
}

/** 校验 keybox 是否为可用的 XML。 */
function validate_keybox(string $kb): bool {
    if ($kb === '' || strlen($kb) < 64) return false;
    return strpos($kb, '<?xml') !== false
        && strpos($kb, '<AndroidAttestation>') !== false
        && strpos($kb, 'BEGIN CERTIFICATE') !== false;
}

/**
 * 目录型源：仓库里存着一大批 keybox XML，列出目录后按「日期轮换」取样，
 * 返回第一个能通过校验（基础 + 可选深度）的。
 */
function fetch_dir_source(array $src, string $accel, int $timeout, int $retries = 3, int $tryCount = 10, ?callable $accept = null, ?array $cfg = null) {
    $repo = trim((string)($src['repo'] ?? ''), '/');
    $dir  = trim((string)($src['dir'] ?? ''), '/');
    if ($repo === '') return false;

    $verifyTls = $cfg === null ? true : omk_http_verify_tls($cfg);

    // 目录列表走带 TTL 的本地缓存：未认证的 GitHub API 只有 60 次/小时，
    // 多个 github_dir 源叠加后每次更新都直连很容易触发限流。
    $list = ($cfg === null)
        ? null
        : omk_http_github_listing($repo, $dir, $cfg, $accel, $timeout);
    if (!is_array($list)) {
        $api = 'https://api.github.com/repos/' . $repo . '/contents/' . $dir;
        $raw = http_get_once($api, $timeout, $verifyTls);
        $list = ($raw === false) ? null : json_decode($raw, true);
        if (!is_array($list)) {
            $raw = http_get($api, $accel, $timeout, 2, $verifyTls);
            $list = ($raw === false) ? null : json_decode($raw, true);
        }
    }
    if (!is_array($list)) return false;

    $files = [];
    foreach ($list as $it) {
        if (!is_array($it)) continue;
        $nm = (string)($it['name'] ?? '');
        $dl = (string)($it['download_url'] ?? '');
        if ($dl === '' || !preg_match('/\.xml$/i', $nm)) continue;
        $files[] = ['name' => $nm, 'url' => $dl];
    }
    if (empty($files)) return false;

    $off = ((int)date('z')) % count($files);
    $n   = min($tryCount, count($files));
    for ($i = 0; $i < $n; $i++) {
        $f = $files[($off + $i) % count($files)];
        $xml = http_get($f['url'], $accel, $timeout, 1, $verifyTls);
        if ($xml === false) continue;
        $xml = kb_to_utf8(trim($xml));
        $xml = trim($xml);
        if (!validate_keybox($xml)) continue;
        if ($accept !== null && !$accept($xml)) continue;
        return ['keybox' => $xml, 'file' => $f['name'], 'tried' => $i + 1];
    }
    return false;
}
