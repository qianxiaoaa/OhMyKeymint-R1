<?php
/**
 * OhMyKeymint-R1 下发统计（PIF）。
 *
 * 计数写在 data_dir/counter.json，web 根之外，只能经 index.php?action=stats 读取。
 * PIF 指纹是静态文件，由 index.php 在转发时自增（每份 .prop 下载 +1）。
 * 在线设备数不由这里统计，见 lib/online.php。
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
    /** @return array{pif:int} */
    function omk_counter_read(array $cfg): array
    {
        $raw = @file_get_contents(omk_counter_path($cfg));
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            $data = [];
        }
        return [
            'pif' => (int)($data['pif'] ?? 0),
        ];
    }
}