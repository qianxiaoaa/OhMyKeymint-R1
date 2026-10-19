<?php
/**
 * OhMyKeymint 下发计数（keybox / pif）。
 *
 * 计数写在 data_dir/counter.json，web 根之外，只能经 index.php?action=stats 读取。
 * keybox 由 index.php 在成功下发时自增；pif 由于是静态文件，由 count_pif.php
 * 解析 nginx 访问日志累积。两者共用本文件的读写逻辑，用 flock 保证并发安全。
 */

declare(strict_types=1);

if (!function_exists('omk_counter_path')) {
    function omk_counter_path(array $cfg): string
    {
        return rtrim((string)$cfg['data_dir'], '/') . '/counter.json';
    }
}

if (!function_exists('omk_counter_bump')) {
    function omk_counter_bump(array $cfg, string $key, int $delta = 1): void
    {
        if ($delta <= 0 || !preg_match('/^[a-z_]+$/', $key)) {
            return;
        }

        $file = omk_counter_path($cfg);
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return;
        }
        if (!@flock($fp, LOCK_EX)) {
            @fclose($fp);
            return;
        }

        $raw = stream_get_contents($fp);
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            $data = [];
        }
        $data[$key] = (int)($data[$key] ?? 0) + $delta;
        $data['updated_at'] = date('Y-m-d H:i:s');

        @ftruncate($fp, 0);
        @rewind($fp);
        @fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        @fflush($fp);
        @flock($fp, LOCK_UN);
        @fclose($fp);
    }
}

if (!function_exists('omk_counter_read')) {
    /** @return array{keybox:int,pif:int} */
    function omk_counter_read(array $cfg): array
    {
        $raw = @file_get_contents(omk_counter_path($cfg));
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            $data = [];
        }
        return [
            'keybox' => (int)($data['keybox'] ?? 0),
            'pif'    => (int)($data['pif'] ?? 0),
        ];
    }
}
