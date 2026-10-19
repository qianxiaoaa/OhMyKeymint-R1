<?php
/**
 * keybox 轮换池 —— 记录「每个上游源各取一份的最新 keybox」，按服务端分发的
 * 顺序轮换下发，让客户端连续申请时拿到不同的 keybox。
 *
 * 数据文件 data/rotation.json（web 根之外），结构：
 *   {
 *     "updated_at": "2026-10-17 12:00:00",
 *     "pool": [
 *       { "source": "yurikey",        "sha256": "<hex>", "size": 12602 },
 *       { "source": "keyboxstatus/1120", "sha256": "<hex>", "size": 12712 },
 *       ...
 *     ],
 *     "index": 0
 *   }
 *
 * pool 数组的顺序就是轮换顺序（与 update_keybox.php 写入的先后一致，每个 enabled
 * 源至多一份）。index 指向「下一次要下发的成员」。keybox 原始内容不落盘在
 * rotation.json，由 action=keybox 按 sha256 去 pool/<sha256>.xml 取文件。
 *
 * 读改写全程 flock 串行化，保证并发请求下轮换只推进一次。
 */

declare(strict_types=1);

if (!function_exists('omk_rotation_path')) {
    function omk_rotation_path(array $cfg): string
    {
        return rtrim((string)$cfg['data_dir'], '/') . '/rotation.json';
    }
}

if (!function_exists('omk_rotation_read')) {
    /** @return array{updated_at:string,pool:array,index:int}|null */
    function omk_rotation_read(array $cfg): ?array
    {
        $file = omk_rotation_path($cfg);
        if (!is_file($file)) {
            return null;
        }
        $j = json_decode((string)@file_get_contents($file), true);
        if (!is_array($j) || !isset($j['pool']) || !is_array($j['pool'])) {
            return null;
        }
        $j['pool'] = array_values(array_filter($j['pool'], fn($m) => is_array($m)));
        $j['index'] = (int)($j['index'] ?? 0);
        return $j;
    }
}

if (!function_exists('omk_rotation_write')) {
    function omk_rotation_write(array $cfg, array $rot): void
    {
        $file = omk_rotation_path($cfg);
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $rot['pool'] = array_values(array_filter($rot['pool'] ?? [], fn($m) => is_array($m)));
        $rot['index'] = (int)($rot['index'] ?? 0);
        @file_put_contents($file, json_encode($rot, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}

/**
 * 原子地取「当前轮换成员并推进一格」。
 *
 * @param callable|null $accept 成员过滤器：返回 false 的成员会被跳过并推进下标，
 *                              用于「已进永久吊销名单的成员绝不下发」。
 * @return array|null null = 没有可用的轮换池；member=null 且 blocked=true 表示
 *                    池里所有成员都被过滤器拒绝。
 */
function omk_rotation_pick(array $cfg, ?callable $accept = null): ?array
{
    $file = omk_rotation_path($cfg);
    $fp = @fopen($file, 'c+');
    if ($fp === false) {
        return null;
    }
    if (!@flock($fp, LOCK_EX)) {
        @fclose($fp);
        return null;
    }

    $rot = omk_rotation_read($cfg);
    if ($rot === null || empty($rot['pool'])) {
        @flock($fp, LOCK_UN);
        @fclose($fp);
        return null;
    }

    $n = count($rot['pool']);
    $start = (int)$rot['index'];
    if ($start < 0 || $start >= $n) {
        $start = 0;
    }

    $chosen = null;
    $chosenIdx = $start;
    for ($i = 0; $i < $n; $i++) {
        $cand = ($start + $i) % $n;
        $m = $rot['pool'][$cand];
        if ($accept === null || $accept($m)) {
            $chosen = $m;
            $chosenIdx = $cand;
            break;
        }
    }

    if ($chosen === null) {
        @flock($fp, LOCK_UN);
        @fclose($fp);
        return ['member' => null, 'index' => $start, 'last' => false, 'blocked' => true, 'pool_size' => $n];
    }

    $isLast = ($chosenIdx === $n - 1);
    $next = ($chosenIdx + 1) % $n;

    // 推进后整体落盘；把新的 index 持久化
    @ftruncate($fp, 0);
    @rewind($fp);
    @fwrite($fp, json_encode([
        'updated_at' => date('Y-m-d H:i:s'),
        'pool'       => $rot['pool'],
        'index'      => $next,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    @fflush($fp);
    @flock($fp, LOCK_UN);
    @fclose($fp);

    return ['member' => $chosen, 'index' => $chosenIdx, 'last' => $isLast, 'blocked' => false, 'pool_size' => $n];
}

/**
 * 只读：从当前指针开始，返回「第 offset 个未吊销成员」，不改动轮换 index。
 * offset=0 即下一个会下发的成员，供 manifest 与 keybox 保持一致；offset=1 供
 * 客户端取「第二份 keybox」（无需推进指针）。offset 大于可下发成员数时返回 null。
 * @param int $offset 0 = 当前待下发成员，1 = 紧随其后的成员，依此类推。
 *                   无 offset 时的旧行为 = offset 0。
 * @return array{member:array,index:int,last:bool}|null
 */
function omk_rotation_peek(array $cfg, ?callable $accept = null, int $offset = 0): ?array
{
    $rot = omk_rotation_read($cfg);
    if ($rot === null || empty($rot['pool'])) {
        return null;
    }
    $n = count($rot['pool']);
    $start = (int)$rot['index'];
    if ($start < 0 || $start >= $n) {
        $start = 0;
    }
    $offset = max(0, $offset);
    $seen = 0;
    for ($i = 0; $i < $n; $i++) {
        $idx = ($start + $i) % $n;
        $m = $rot['pool'][$idx];
        if ($accept !== null && !$accept($m)) {
            continue;
        }
        if ($seen === $offset) {
            return ['member' => $m, 'index' => $idx, 'last' => ($idx === $n - 1)];
        }
        $seen++;
    }
    return null;
}

/**
 * 只读：按轮换顺序返回全部未吊销成员（从当前指针开始，filtered），供 manifest
 * 把成员级 sha256 / 签名 / 有效性随清单一并下发。输出顺序与「action=keybox 带
 * 相同 offset」返回的成员一一对应，即 pool[0] 恒等于下一次 action=keybox 会
 * 下发的那份，pool[offset] 恒等于 action=keybox&offset=offset 那份。
 *
 * @return array{pool:array,index:int,excluded:int}|null null = 没有轮换池
 */
function omk_rotation_snapshot(array $cfg, ?callable $accept = null): ?array
{
    $rot = omk_rotation_read($cfg);
    if ($rot === null || empty($rot['pool'])) {
        return null;
    }
    $n = count($rot['pool']);
    $start = (int)$rot['index'];
    if ($start < 0 || $start >= $n) {
        $start = 0;
    }
    $pool = [];
    $excluded = 0;
    for ($i = 0; $i < $n; $i++) {
        $idx = ($start + $i) % $n;
        $m = $rot['pool'][$idx];
        if ($accept !== null && !$accept($m)) {
            $excluded++;
            continue;
        }
        $pool[] = [
            'source'         => (string)($m['source'] ?? ''),
            'sha256'         => (string)($m['sha256'] ?? ''),
            'size'           => (int)($m['size'] ?? 0),
            'signature'      => (string)($m['signature'] ?? ''),
            'days_remaining' => $m['days_remaining'] ?? null,
            'min_not_after'  => $m['min_not_after'] ?? null,
        ];
    }
    if (empty($pool)) {
        $pool[] = [
            'source'         => '',
            'sha256'         => '',
            'size'           => 0,
            'signature'      => '',
            'days_remaining' => null,
            'min_not_after'  => null,
        ];
    }
    return ['pool' => $pool, 'index' => $start, 'excluded' => $excluded];
}

if (!function_exists('omk_rotation_next_index')) {
    /** 只读：下一个将要下发的成员下标（index.php 用它渲染 manifest 的 current_index）。 */
    function omk_rotation_next_index(array $cfg): int
    {
        $rot = omk_rotation_read($cfg);
        if ($rot === null || empty($rot['pool'])) {
            return 0;
        }
        $idx = (int)$rot['index'];
        if ($idx < 0 || $idx >= count($rot['pool'])) {
            return 0;
        }
        return $idx;
    }
}
