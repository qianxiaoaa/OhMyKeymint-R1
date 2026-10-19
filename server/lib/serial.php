<?php
/**
 * 证书序列号规范化 —— keybox 校验与吊销名单共用的唯一实现。
 *
 * 为什么必须集中：keybox 证书里的序列号来自 openssl 的 serialNumberHex，
 * 而 Google attestation/status 的键是十进制；两个模块各自实现一套转换时，
 * 大小写、前导零、是否带 0x 的细微差异都会让吊销比对静默失配——这正是
 * 「已吊销 keybox 仍被下发」的根因之一。
 *
 * 统一规则：内部一律使用【大写、无分隔符、按整字节补零】的十六进制串。
 */

declare(strict_types=1);

if (!function_exists('omk_dec_to_hex')) {
    /**
     * 十进制字符串转十六进制（纯 PHP，不依赖 gmp/bcmath）。
     * 逐位长除法，能正确处理远超浮点精度的证书序列号。
     */
    function omk_dec_to_hex(string $dec): string
    {
        $dec = ltrim($dec, '0');
        if ($dec === '') {
            return '0';
        }
        if (!ctype_digit($dec)) {
            return '';
        }
        $hex = '';
        $digits = $dec;
        while ($digits !== '') {
            $rem = 0;
            $q = '';
            $len = strlen($digits);
            for ($i = 0; $i < $len; $i++) {
                $cur = $rem * 10 + (int)$digits[$i];
                $qd = intdiv($cur, 16);
                $rem = $cur % 16;
                if ($q !== '' || $qd !== 0) {
                    $q .= (string)$qd;
                }
            }
            $hex = strtoupper(dechex($rem)) . $hex;
            $digits = $q;
        }
        return $hex === '' ? '0' : $hex;
    }
}

if (!function_exists('omk_norm_serial_hex')) {
    /**
     * 规范化十六进制序列号：
     *   1. 去掉 0x / 冒号 / 空格 / 横线，转大写；
     *   2. 补齐成整字节后去掉前导零，再补齐一次，避免 "09.." 与 "9.." 失配。
     */
    function omk_norm_serial_hex(string $hex): string
    {
        $hex = strtoupper((string)preg_replace('/[^0-9A-Fa-f]/', '', $hex));
        if ($hex === '') {
            return '';
        }
        if (strlen($hex) % 2 === 1) {
            $hex = '0' . $hex;
        }
        $hex = ltrim($hex, '0');
        if ($hex === '') {
            return '0';
        }
        if (strlen($hex) % 2 === 1) {
            $hex = '0' . $hex;
        }
        return $hex;
    }
}

if (!function_exists('omk_serial_to_hex')) {
    /**
     * 任意书写形式 -> 规范十六进制。
     *   - "0x1A2B"、带分隔符的十六进制：按十六进制规范化；
     *   - 纯十进制：按十进制转换；
     *   - 其它：按十六进制规范化（容忍不带前缀的十六进制）。
     */
    function omk_serial_to_hex(string $serial): string
    {
        $serial = trim($serial);
        if ($serial === '') {
            return '';
        }
        if (str_starts_with(strtolower($serial), '0x')) {
            return omk_norm_serial_hex(substr($serial, 2));
        }
        if (ctype_digit($serial)) {
            return omk_dec_to_hex($serial);
        }
        return omk_norm_serial_hex($serial);
    }
}
