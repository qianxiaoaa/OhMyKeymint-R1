<?php
/**
 * 下载层 —— 重试、GitHub 加速、TLS 校验、GitHub 目录列表缓存。
 *
 * 旧实现把 curl / file_get_contents 直接写死在 sources.php 里，并且固定
 * CURLOPT_SSL_VERIFYPEER=false：任何网络中间人都能替换 keybox 或吊销名单。
 * 这里改为默认开启校验，只有显式配置 http_verify_tls=false 才关闭。
 */

declare(strict_types=1);

if (!function_exists('omk_http_verify_tls')) {
    function omk_http_verify_tls(array $cfg): bool
    {
        return !array_key_exists('http_verify_tls', $cfg) || !empty($cfg['http_verify_tls']);
    }
}

if (!function_exists('omk_http_backoff')) {
    /** 轻度退避，避免对上游连续打空请求。 */
    function omk_http_backoff(int $attempt): void
    {
        if ($attempt <= 1) {
            return;
        }
        usleep(min(1000, 150 * ($attempt - 1)) * 1000);
    }
}

if (!function_exists('http_get_once')) {
    /**
     * 单次 HTTP GET。
     * @return string|false
     */
    function http_get_once(string $url, int $timeout, bool $verifyTls = true)
    {
        if (function_exists('curl_init')) {
            $ch = curl_init();
            $opts = [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 5,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_CONNECTTIMEOUT => 15,
                CURLOPT_SSL_VERIFYPEER => $verifyTls,
                CURLOPT_SSL_VERIFYHOST => $verifyTls ? 2 : 0,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (OhMyKeymint-server)',
            ];
            curl_setopt_array($ch, $opts);
            $data = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if ($code >= 200 && $code < 300 && $data !== false && $data !== '') {
                return $data;
            }
            return false;
        }

        $ctx = stream_context_create([
            'http' => [
                'timeout'       => $timeout,
                'user_agent'    => 'Mozilla/5.0 (OhMyKeymint-server)',
                'follow_location' => 1,
                'max_redirects' => 5,
            ],
            'ssl'  => [
                'verify_peer'      => $verifyTls,
                'verify_peer_name' => $verifyTls,
            ],
        ]);
        $data = @file_get_contents($url, false, $ctx);
        return ($data !== false && $data !== '') ? $data : false;
    }
}

if (!function_exists('http_get')) {
    /**
     * 下载（GitHub 源先走加速前缀，失败重试，再直连重试）。
     */
    function http_get(string $url, string $accel, int $timeout, int $retries = 3, bool $verifyTls = true)
    {
        $retries = max(1, $retries);
        $isGithub = (strpos($url, 'github.com') !== false)
            || (strpos($url, 'raw.githubusercontent.com') !== false)
            || (strpos($url, 'api.github.com') !== false);

        $candidates = [];
        if ($isGithub && $accel !== '' && strpos($url, $accel) !== 0) {
            $candidates[] = rtrim($accel, '/') . '/' . ltrim($url, '/');
        }
        $candidates[] = $url;

        foreach ($candidates as $target) {
            for ($i = 1; $i <= $retries; $i++) {
                $data = http_get_once($target, $timeout, $verifyTls);
                if ($data !== false) {
                    return $data;
                }
                omk_http_backoff($i);
            }
        }
        return false;
    }
}

if (!function_exists('omk_http_cache_dir')) {
    function omk_http_cache_dir(array $cfg): string
    {
        return rtrim((string)$cfg['data_dir'], '/') . '/cache';
    }
}

if (!function_exists('omk_http_github_listing')) {
    /**
     * 读取 GitHub contents API 目录列表，带本地 TTL 缓存。
     *
     * 未认证的 GitHub API 只有 60 次/小时；原来的实现每次更新都直连，
     * 多个 github_dir 源叠加后容易触发限流，进而把整轮更新拖成「全部下载失败」。
     *
     * @return array<int,array>|null
     */
    function omk_http_github_listing(string $repo, string $dir, array $cfg, string $accel, int $timeout): ?array
    {
        $repo = trim($repo, '/');
        $dir = trim($dir, '/');
        if ($repo === '') {
            return null;
        }

        $ttl = max(0, (int)($cfg['github_listing_ttl'] ?? 21600));
        $cacheDir = omk_http_cache_dir($cfg);
        $cacheFile = $cacheDir . '/gh_' . sha1($repo . '/' . $dir) . '.json';

        if ($ttl > 0 && is_file($cacheFile)) {
            $cached = json_decode((string)@file_get_contents($cacheFile), true);
            if (is_array($cached)
                && isset($cached['fetched_at'], $cached['items'])
                && is_array($cached['items'])
                && (time() - (int)$cached['fetched_at']) < $ttl) {
                return $cached['items'];
            }
        }

        $api = 'https://api.github.com/repos/' . $repo . '/contents/' . $dir;
        $raw = http_get_once($api, $timeout, omk_http_verify_tls($cfg));
        if ($raw === false) {
            $raw = http_get($api, $accel, $timeout, 2, omk_http_verify_tls($cfg));
        }
        $items = ($raw === false) ? null : json_decode($raw, true);
        if (!is_array($items)) {
            return null;
        }

        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0755, true);
        }
        @file_put_contents($cacheFile, json_encode([
            'fetched_at' => time(),
            'repo'       => $repo,
            'dir'        => $dir,
            'items'      => $items,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        return $items;
    }
}
