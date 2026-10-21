<?php
/**
 * OhMyKeymint-R1 在线设备统计。
 *
 * 客户端（OMK 模块，keystore 身份）每 online_interval 秒向
 * `index.php?action=report` POST 一次心跳：module_id（安装内生成的
 * 独立设备号）+ keybox_sha256（当前已安装 keybox 的 SHA-256，可能为空）。
 *
 * 服务端丢弃超过 online_window 秒未见心跳的设备，得到一个「当前
 * 正常运行设备数」。这个数来自真实的活跃心跳，是可辩护的存活度量；
 * 与旧的 keybox 下发计数（每次轮换都 +1，无法区分设备）无关。
 *
 * 隐私/稳健性权衡：
 *   - 只存储 module_id 的 SHA-256 前 20 个 hex 作为去重键（80 bit，
 *     20 万设备规模碰撞概率可忽略），不落原始 module_id；
 *   - 单设备两次心跳之间至少隔 online_interval/2 秒才算一次有效保活，
 *     避免高频重放无限续期；
 *   - 设备数达到 online_max_devices 后不再接受新设备入表，只更新已存在者；
 *   - 所有写都走 flock，避免并发 PHP 进程写坏文件。
 */

declare(strict_types=1);

if (!function_exists('omk_online_path')) {
    function omk_online_path(array $cfg): string
    {
        return rtrim((string)$cfg['data_dir'], '/') . '/online.json';
    }
}

if (!function_exists('omk_online_id_key')) {
    /** 去重键：module_id 的 SHA-256 前 20 个 hex，不存原始值。 */
    function omk_online_id_key(string $id): string
    {
        return substr(hash('sha256', $id), 0, 20);
    }
}

if (!function_exists('omk_online_valid_sha')) {
    function omk_online_valid_sha(string $sha): bool
    {
        return preg_match('/^[0-9a-f]{64}$/', $sha) === 1;
    }
}

if (!function_exists('omk_online_lock_read')) {
    /** 读取并顺手做窗口裁剪，返回（data, fp）——写路径复用同一把锁。 */
    function omk_online_lock_read(array $cfg, $fp): array
    {
        $window = max(60, (int)($cfg['online_window'] ?? 21600));
        $now = time();
        $raw = stream_get_contents($fp);
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            $data = [];
        }
        $devices = is_array($data['devices'] ?? null) ? $data['devices'] : [];
        foreach ($devices as $key => $entry) {
            if (!is_array($entry) || !isset($entry['last_seen']) || $now - (int)$entry['last_seen'] > $window) {
                unset($devices[$key]);
            }
        }
        $data['devices'] = $devices;
        return [$data, $now, $window];
    }
}

if (!function_exists('omk_online_persist')) {
    function omk_online_persist($fp, array $data): void
    {
        @ftruncate($fp, 0);
        @rewind($fp);
        @fwrite($fp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        @fflush($fp);
    }
}

if (!function_exists('omk_online_ingest')) {
    /**
     * 处理一次心跳上报。
     * @return array{ok:bool,devices:int,peak:int}
     */
    function omk_online_ingest(array $cfg, array $in): array
    {
        $idField = (string)($cfg['online_id_field'] ?? 'module_id');
        $id = (string)($in[$idField] ?? '');
        $fail = function () use ($cfg): array {
            $r = omk_online_read($cfg);
            return ['ok' => false, 'devices' => $r['devices'], 'peak' => $r['peak']];
        };

        // 模块独立设备号格式：omk- 开头，后接 16..64 个 hex。
        if (preg_match('/^omk-[0-9a-f]{16,64}$/', $id) !== 1) {
            return $fail();
        }
        $sha = (string)($in['keybox_sha256'] ?? '');
        if ($sha !== '' && !omk_online_valid_sha($sha)) {
            return $fail();
        }
        $window = max(60, (int)($cfg['online_window'] ?? 21600));
        $cap = max(1, (int)($cfg['online_max_devices'] ?? 200000));
        $minInterval = max(30, (int)(($cfg['online_interval'] ?? 1800) / 2));

        $file = omk_online_path($cfg);
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return ['ok' => false, 'devices' => 0, 'peak' => 0];
        }
        if (!@flock($fp, LOCK_EX)) {
            @fclose($fp);
            return $fail();
        }

        [$data, $now] = omk_online_lock_read($cfg, $fp);
        $devices = $data['devices'];
        $key = omk_online_id_key($id);
        $isNew = !isset($devices[$key]);
        $peak = max((int)($data['peak'] ?? 0), count($devices));

        if ($isNew && count($devices) >= $cap) {
            // 已达上限：拒绝新设备，避免文件无限膨胀。
            omk_online_persist($fp, ['devices' => $devices, 'peak' => $peak]);
            @flock($fp, LOCK_UN);
            @fclose($fp);
            return ['ok' => false, 'devices' => count($devices), 'peak' => $peak];
        }

        $last = $isNew ? 0 : (int)($devices[$key]['last_seen'] ?? 0);
        // 单设备两次有效保活之间必须隔开 minInterval，避免高频重放无限续期。
        if ($isNew || $now - $last >= $minInterval) {
            $devices[$key] = ['last_seen' => $now, 'keybox' => $sha];
        }

        $data['devices'] = $devices;
        $data['peak'] = max($peak, count($devices));
        $data['updated_at'] = date('Y-m-d H:i:s');
        omk_online_persist($fp, $data);
        @flock($fp, LOCK_UN);
        @fclose($fp);

        return ['ok' => true, 'devices' => count($devices), 'peak' => $data['peak']];
    }
}

if (!function_exists('omk_online_read')) {
    /** 只读在线统计（会先裁剪过期窗口）。@return array{devices:int,peak:int,keybox_distinct:int,updated_at:string} */
    function omk_online_read(array $cfg): array
    {
        $file = omk_online_path($cfg);
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return ['devices' => 0, 'peak' => 0, 'keybox_distinct' => 0, 'updated_at' => ''];
        }
        if (!@flock($fp, LOCK_EX)) {
            @fclose($fp);
            return ['devices' => 0, 'peak' => 0, 'keybox_distinct' => 0, 'updated_at' => ''];
        }
        [$data] = omk_online_lock_read($cfg, $fp);
        @flock($fp, LOCK_UN);
        @fclose($fp);

        $devices = $data['devices'];
        $distinct = [];
        foreach ($devices as $entry) {
            $sha = (string)($entry['keybox'] ?? '');
            if ($sha !== '') {
                $distinct[$sha] = true;
            }
        }
        return [
            'devices'         => count($devices),
            'peak'            => (int)($data['peak'] ?? 0),
            'keybox_distinct' => count($distinct),
            'updated_at'      => (string)($data['updated_at'] ?? ''),
        ];
    }
}