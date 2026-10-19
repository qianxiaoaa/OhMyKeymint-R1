<?php
/**
 * keybox 有效性校验 —— 回答"这份 keybox 现在还能用吗"。
 *
 * 背景：客户端只验"签名 + sha256"，证明文件来自本服务器且未被篡改，
 * 但**不证明 keybox 本身仍然有效**。keybox 里装的是 Google 硬件认证的
 * 私钥与证书链，一旦证书过期或被吊销，注入照样成功、开机也正常，
 * 只有依赖硬件认证的 App（支付/银行）会静默失效，极难排查。
 * 本模块在服务端把这件事查清楚，并把结论写进 manifest 供客户端决策。
 *
 * 注意：提取证书必须用 PEM 标记（-----BEGIN CERTIFICATE-----），
 * **不能**用 <Certificate>...</Certificate> 正则——XML 标签会连带
 * format="pem" 属性和后续节点，导致 base64 被截断、解析全失败。
 */

declare(strict_types=1);

require_once __DIR__ . '/serial.php';

/** 从 keybox XML 中提取所有 PEM 证书并解析 */
function kb_extract_certs(string $kb): array {
    $certs = [];
    if (!preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $kb, $m)) {
        return $certs;
    }
    foreach ($m[1] as $b64) {
        $b64 = preg_replace('/\s+/', '', $b64);
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split($b64, 64, "\n") . "-----END CERTIFICATE-----\n";
        $x = @openssl_x509_parse($pem);
        if ($x === false) {
            $certs[] = ['parsed' => false];
            continue;
        }
        $name = function ($n) {
            if (!is_array($n)) return (string)$n;
            foreach (['CN', 'OU', 'O'] as $k) {
                if (!empty($n[$k])) return (string)$n[$k];
            }
            // Google 硬件认证链的 subject 只有 serialNumber=<hex>，没有 CN/OU/O。
            // 不回退的话整条链的主题全是空串，设备端「密钥自检」展示出来一片空白，
            // 也没法判断链尾到底是不是根。
            if (!empty($n['serialNumber'])) return 'serialNumber=' . $n['serialNumber'];
            $parts = [];
            foreach ($n as $k => $v) {
                if (is_string($v) && $v !== '') $parts[] = $k . '=' . $v;
            }
            return implode(', ', $parts);
        };
        $certs[] = [
            'parsed'      => true,
            'pem'         => $pem,
            'subject'     => $name($x['subject'] ?? ''),
            'issuer'      => $name($x['issuer'] ?? ''),
            // 统一用规范十六进制：openssl 给的是十进制 serialNumber 与十六进制
            // serialNumberHex，两者混用会让吊销列表静默失配，所以只认一个格式。
            'serial'      => kb_norm_serial((string)($x['serialNumberHex'] ?? '')),
            'not_before'  => (int)($x['validFrom_time_t'] ?? 0),
            'not_after'   => (int)($x['validTo_time_t'] ?? 0),
            'is_ca'       => (bool)($x['extensions']['basicConstraints'] ?? false),
            'raw'         => $x,
        ];
    }
    return $certs;
}

/**
 * 校验单条证书链：逐张验签 + 查有效期。
 * keybox 里最后一张通常是中间 CA，其上层（Google 根）不在文件内，
 * 所以链尾"验不过"是正常的，不算错误。
 */
function kb_check_chain(array $certs, int $now, array $revoked): array {
    $out = [
        'count'          => count($certs),
        'expired'        => [],
        'not_yet_valid'  => [],
        'unparsable'     => 0,
        'chain_broken'   => [],
        'revoked'        => [],
        'expected'       => null,
        'min_not_after'  => null,
        'serials'        => [],
    ];
    foreach ($certs as $i => $c) {
        if (empty($c['parsed'])) { $out['unparsable']++; continue; }
        $out['serials'][] = $c['serial'];
        if ($c['not_after'] > 0) {
            if ($c['not_after'] < $now) $out['expired'][] = $i;
            if ($out['min_not_after'] === null || $c['not_after'] < $out['min_not_after']) {
                $out['min_not_after'] = $c['not_after'];
            }
        }
        if ($c['not_before'] > 0 && $c['not_before'] > $now) $out['not_yet_valid'][] = $i;
        if ($c['serial'] !== '' && in_array($c['serial'], $revoked, true)) $out['revoked'][] = $i;
    }
    // 逐张验签：certs[i] 应由 certs[i+1] 签发
    for ($i = 0; $i + 1 < count($certs); $i++) {
        if (empty($certs[$i]['parsed']) || empty($certs[$i + 1]['parsed'])) continue;
        if (!@openssl_x509_verify($certs[$i]['pem'], $certs[$i + 1]['pem'])) {
            $out['chain_broken'][] = $i;
        }
    }
    return $out;
}

/**
 * 规范化证书序列号的十六进制表示。
 * 去掉"整字节"的前导零（0x00 填充），但**不能**剥成奇数字符数——
 * openssl 对首字节高位为 1 的序列号会输出 "09307822..." 这种带填充零的
 * 形式，剥成奇数位会与另一种表示不一致，导致吊销比对静默失配。
 */
function kb_norm_serial(string $hex): string {
    $hex = strtoupper(str_replace([':', ' ', '-'], '', trim($hex)));
    if ($hex === '' || !preg_match('/^[0-9A-F]+$/', $hex)) return $hex;
    return omk_norm_serial_hex($hex);
}

/**
 * 十进制字符串转十六进制（纯 PHP，不依赖 gmp/bcmath——生产环境这两个都没装）。
 * 用 long division 逐位求余，能正确处理远超浮点精度的证书序列号。
 */
function kb_dec_to_hex(string $dec): string {
    return omk_dec_to_hex($dec);
}

/**
 * 规范化吊销列表：统一成规范十六进制。
 * 允许配置里混写十进制或十六进制（带不带 0x 都行），避免静默失配。
 */
function kb_normalize_revoked(array $list): array {
    $out = [];
    foreach ($list as $s) {
        $s = strtoupper(trim((string)$s));
        if ($s === '') continue;
        $hexForm = (strpos($s, '0X') === 0);
        if ($hexForm) $s = substr($s, 2);
        $s = str_replace([':', ' ', '-'], '', $s);
        if ($s === '') continue;
        if (!$hexForm && ctype_digit($s)) {
            // 纯十进制（最典型的误配来源）：转成十六进制
            $s = kb_dec_to_hex($s);
        } elseif (!preg_match('/^[0-9A-F]+$/', $s)) {
            continue;   // 既不是十进制也不是十六进制，忽略
        }
        $out[] = kb_norm_serial($s);
    }
    return array_values(array_unique($out));
}

/**
 * 完整有效性报告。
 *
 * @param string $kb      keybox XML 内容
 * @param array  $revoked 已知被吊销的证书序列号（十六进制或十进制均可）
 * @return array 结构化报告
 */
function kb_validity_report(string $kb, array $revoked = []): array {
    $now = time();
    $revoked = kb_normalize_revoked($revoked);
    $rep = [
        'ok'       => false,
        'level'    => 'invalid',   // valid | warning | invalid
        'reasons'  => [],
        'warnings' => [],
        'checked_at' => date('Y-m-d H:i:s'),
    ];

    if ($kb === '' || strpos($kb, '<AndroidAttestation>') === false) {
        $rep['reasons'][] = '不是有效的 keybox XML';
        return $rep;
    }

    // ---- 结构检查 ----
    preg_match('/<NumberOfKeyboxes>(\d+)</', $kb, $nk);
    $declaredKeyboxes = isset($nk[1]) ? (int)$nk[1] : null;
    $rep['declared_keyboxes'] = $declaredKeyboxes;
    $rep['keybox_blocks']     = substr_count($kb, '<Keybox');
    $rep['key_count']         = substr_count($kb, '<Key ');
    // 用正则而不是 substr_count：RSA 私钥的 PEM 头是 "BEGIN RSA PRIVATE KEY"，
    // 它既不包含 "BEGIN EC PRIVATE KEY" 也不包含 "BEGIN PRIVATE KEY"，
    // 旧写法会把合法的 RSA keybox 直接误判成「缺少私钥」而丢弃。
    $rep['private_keys']      = (int)preg_match_all('/BEGIN [A-Z0-9 ]*PRIVATE KEY/', $kb);
    $rep['cert_markers']      = substr_count($kb, 'BEGIN CERTIFICATE') + substr_count($kb, 'BEGIN RSA CERTIFICATE');

    if ($rep['private_keys'] < 1) {
        $rep['reasons'][] = '缺少私钥（未找到任何 BEGIN ... PRIVATE KEY）';
    }
    if ($rep['cert_markers'] < 2) {
        $rep['reasons'][] = '证书数量过少（' . $rep['cert_markers'] . ' 张）';
    }
    if ($declaredKeyboxes !== null && $declaredKeyboxes !== $rep['keybox_blocks']) {
        $rep['warnings'][] = "声明的 Keybox 数({$declaredKeyboxes}) 与实际({$rep['keybox_blocks']}) 不一致";
    }

    // ---- 逐条链检查 ----
    preg_match_all('/<CertificateChain>(.*?)<\/CertificateChain>/s', $kb, $chains);
    if (empty($chains[1])) {
        $rep['reasons'][] = '未找到 CertificateChain 段';
        return $rep;
    }

    $allExpired = false; $anyValid = false; $allSerials = [];
    $rep['chains'] = [];
    foreach ($chains[1] as $ci => $chainXml) {
        preg_match('/<NumberOfCertificates>(\d+)</', $chainXml, $nc);
        $certs = kb_extract_certs($chainXml);
        $chk = kb_check_chain($certs, $now, $revoked);
        $chk['declared'] = isset($nc[1]) ? (int)$nc[1] : null;
        $chk['certs'] = array_map(function ($c) {
            return empty($c['parsed']) ? ['parsed' => false] : [
                'parsed'     => true,
                'subject'    => $c['subject'],
                'issuer'     => $c['issuer'],
                'serial'     => $c['serial'],
                'not_before' => date('Y-m-d', $c['not_before']),
                'not_after'  => date('Y-m-d', $c['not_after']),
            ];
        }, $certs);

        if ($chk['declared'] !== null && $chk['declared'] !== $chk['count']) {
            $rep['warnings'][] = "chain#{$ci} 声明的证书数({$chk['declared']}) 与实际({$chk['count']}) 不一致";
        }
        if ($chk['unparsable'] > 0) {
            $rep['reasons'][] = "chain#{$ci} 有 {$chk['unparsable']} 张证书无法解析";
        }
        if (!empty($chk['revoked'])) {
            $rep['reasons'][] = "chain#{$ci} 含已吊销证书（位置 " . implode(',', $chk['revoked']) . "）";
        }
        if (!empty($chk['not_yet_valid'])) {
            $rep['reasons'][] = "chain#{$ci} 含尚未生效的证书";
        }
        if (!empty($chk['chain_broken'])) {
            $rep['reasons'][] = "chain#{$ci} 链验证失败（位置 " . implode(',', $chk['chain_broken']) . "）";
        }
        if (!empty($chk['expired']) && count($chk['expired']) >= $chk['count']) {
            $allExpired = true;
        }
        if (empty($chk['expired']) && $chk['count'] > 0) {
            $anyValid = true;
        }
        $allSerials = array_merge($allSerials, $chk['serials']);
        $rep['chains'][] = $chk;
    }

    if ($allExpired) {
        $rep['reasons'][] = '所有证书链均已过期';
    } elseif (!$anyValid) {
        $rep['reasons'][] = '没有一条完整的有效证书链';
    }

    // ---- 剩余有效期 ----
    $minAfter = null;
    foreach ($rep['chains'] as $c) {
        if ($c['min_not_after'] !== null && ($minAfter === null || $c['min_not_after'] < $minAfter)) {
            $minAfter = $c['min_not_after'];
        }
    }
    $rep['min_not_after']    = $minAfter ? date('Y-m-d', $minAfter) : null;
    $rep['days_remaining']   = $minAfter ? (int)floor(($minAfter - $now) / 86400) : null;
    $rep['serials']          = array_values(array_unique(array_filter($allSerials)));
    if ($rep['days_remaining'] !== null && $rep['days_remaining'] < 90 && $rep['days_remaining'] >= 0) {
        $rep['warnings'][] = "证书将在 {$rep['days_remaining']} 天后过期";
    }

    // ---- 结论 ----
    if (empty($rep['reasons'])) {
        $rep['ok'] = true;
        $rep['level'] = empty($rep['warnings']) ? 'valid' : 'warning';
    } else {
        $rep['ok'] = false;
        $rep['level'] = 'invalid';
    }
    return $rep;
}
