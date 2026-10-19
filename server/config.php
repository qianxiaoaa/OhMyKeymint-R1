<?php
/**
 * OhMyKeymint 云端服务端配置。
 *
 * 自包含：只依赖同目录的 lib/。
 *
 * 部署：把整个 server/ 目录放到不可从 web 直接访问的位置，并把网站 URL 前缀
 * `/api/omk` 指向 `server/public/`。客户端按下面的 base_url 取：
 *   <base>/index.php?action=manifest  清单（sha256 + Ed25519 签名 + 有效性报告）
 *   <base>/index.php?action=keybox    当前 keybox（&offset=N 取第 N 份，不推进轮换）
 *   <base>/index.php?action=revocation_report  客户端吊销证据上报（POST/GET）
 *   <base>/pif/device_list.json       PIF 指纹目录（静态文件）
 *   <base>/pif/device_prop/<product>.prop
 *
 * 结构性说明：
 *   - `public/` 是 web 根。只有 `index.php`（Keybox/manifest 前端控制器）和
 *     `pif/`（静态指纹 feed）位于其中，可直接访问。
 *   - `data/`（keybox.xml / manifest.json / revocation.json / pool/）是私有数据，
 *     放在 web 根之外，只能由 `index.php` 通过 action 参数读取。
 *   - `keys/`、`lib/`、`update_*.php` 同样在 web 根之外，不会被直接访问。
 */
return [
    // 对客户端可见的基础地址（必须以 http(s):// 开头，无结尾斜杠）
    'base_url' => 'https://omk.5ijxa.com/api/omk',

    // 私有数据目录（keybox.xml / manifest.json / revocation.json / pool/，web 根之外）
    'data_dir' => __DIR__ . '/data',

    // 公开的 PIF 指纹 feed 目录（web 根内，静态文件；URL 契约不变）
    'pif_dir' => __DIR__ . '/public/pif',

    // 密钥目录（Ed25519 私钥/公钥，web 根之外）
    'keys_dir' => __DIR__ . '/keys',

    'keybox_in' => 'keybox.xml',
    'version'      => 'v1.3.6',
    'version_code' => 100,

    // 人工固定 keybox：文件存在且校验通过时，update_keybox.php 永远优先用它，
    // 不再被上游源覆盖（A/B 实验/回滚用：删掉该文件即恢复自动择优）。
    'keybox_pin' => __DIR__ . '/qianxiaokey.xml',

    // GitHub 加速前缀：github.com 源先走此加速，失败再直连。
    'github_accel' => 'https://gh-proxy.com/',

    // 下载重试次数 / 单次超时秒
    'download_retries' => 3,
    'timeout' => 60,

    // TLS 证书校验。默认开启；只有上游确实使用自签证书时才关闭。
    'http_verify_tls' => true,
    // GitHub contents API 目录列表缓存（秒）；未认证 API 每小时仅 60 次。
    'github_listing_ttl' => 21600,

    // nginx 访问日志：count_pif.php 靠它统计 PIF（静态文件）下发次数；
    // 留空则用 count_pif.php 内置默认路径 /www/wwwlogs/<站点>.log
    'access_log' => '/www/wwwlogs/omk.5ijxa.com.log',

    // ---- keybox 上游源（每个 enabled 源各取一份最新有效 keybox，轮换下发）----
    // 不再用 priority 择优：update_keybox.php 每轮从每个 enabled 源各取一份有效
    // keybox 组成轮换池，index.php 按池顺序轮换下发（客户端连续申请会依次拿到
    // 不同来源的 keybox）。github_dir 型源另有自已的按日取样逻辑。
    'sources' => [
        'yurikey' => [
            'enabled'  => true,
            'url'      => 'https://raw.githubusercontent.com/Yurii0307/yurikey/main/key',
            'type'     => 'base64',
        ],
        // MeowDump/MeowDump 的 NullVoid/OptimusPrime 与 Megatron 两个旧路径均已 404
        // （仓库 main 分支已无这些文件），已剔除；用 keyboxcollection 补位。
        'keyboxcollection' => [
            'enabled'  => true,
            'type'     => 'github_dir',
            'repo'     => 'rahmatsobrian/keybox-collection',
            'dir'      => '',
        ],
        'keyboxhub' => [
            'enabled'  => true,
            'type'     => 'github_dir',
            'repo'     => 'shall0e/KeyboxHub',
            'dir'      => 'KeyboxHub',
        ],
        'keyboxstatus' => [
            'enabled'  => true,
            'type'     => 'github_dir',
            'repo'     => 'SSM-FX/KeyboxStatus',
            'dir'      => '',
        ],
    ],

    /**
     * 吊销名单（Google attestation/status）多源。
     *
     * 更新脚本会并行拉取**全部**源并合并结果（任一源缺失都不会覆盖其它源的
     * 命中），快照写入私有 data/revocation.json。命中可信源或同时被 ≥2 个源
     * 收录的序列号会并入永久吊销名单 data/revoked_permanent.json，轮换池入池
     * 与每次下发前都会以永久名单做最终拦截。
     *
     * 官方地址在国内服务器常常连不通，因此镜像排在前面；官方地址保留作兜底。
     */
    'revocation_sources' => [
        'purainity' => 'https://raw.githubusercontent.com/purainity/keybox-tools/main/res/status.json',
        'kimmyxyc'  => 'https://raw.githubusercontent.com/KimmyXYC/KeyboxChecker/main/res/json/status.json',
        'google'    => 'https://android.googleapis.com/attestation/status',
    ],
    // 吊销名单缓存新鲜度（秒）与单源超时（秒）
    'revocation_max_age' => 86400,
    'revocation_timeout' => 20,

    // 可信吊销来源：命中任一即可写入永久名单（单源、未列出的镜像只作参考）
    'revocation_trusted_sources' => ['google', 'purainity', 'kimmyxyc'],

    // ---- 客户端吊销证据上报 ----
    // 客户端只上报：证书序列号、keybox SHA-256、来源、检测时间。
    // 达到 report_threshold 个独立设备上报后，该序列号写入永久吊销名单。
    'report_threshold'    => 2,
    'report_rate_limit'   => 20,   // 单个上报者每窗口最多条数
    'report_rate_window'  => 3600, // 限流窗口（秒）

    // 已知被吊销的证书序列号（十进制或十六进制混写均可）
    'revoked_serials' => [
        // '64DEAA4D53885472AFAC267BDBD4A472',
    ],

    // Ed25519 签名（防盗，需 PHP sodium）
    'sign_enable'     => true,
    'sign_public_out' => 'ed25519.pub',
    'sign_secret_in'  => 'ed25519.key',

    // ---- PIF 指纹聚合源 ----
    // 每个源给出「如何从上游拿到 PIF 指纹」。type=github_release 表示扫描该仓库
    // 最新 release 的资产，挑出能解析为 Google Pixel 指纹的 .json/.prop 文件。
    // 服务器会归一化成 OMK 客户端能直接消费的 device_list.json + device_prop/*.prop。
    // 只保留实测能产出指纹的源：JingMatrix/PlayIntegrityFix 无 release、
    // IR0NBYTE/playIntegrityFixDetector 的 release 无 json/prop 资产，均已移除。
    'pif_sources' => [
        'elcapitanoe' => [
            'enabled'  => true,
            'type'     => 'github_release',
            'repo'     => 'Elcapitanoe/PIF-Config-Generator',
            'priority' => 1,
            'asset'    => '/\.json$/i',
        ],
        'xprateek' => [
            'enabled'  => true,
            'type'     => 'github_release',
            'repo'     => 'xprateek/PIF-JSON-Generator',
            'priority' => 1,
            'asset'    => '/\.json$/i',
        ],
    ],

    // 客户端可见的 PIF feed 上限（与 OMK 客户端契约一致）
    'pif_max_devices' => 64,

    // ---- 云端通告（随 manifest 下发，客户端在每次获取 keybox 时展示）----
    // 每条会按顺序展示在客户端云 keybox 弹窗里（成功获取后也会再次提示）。
    // 留空数组表示不下发任何通告。
    'notice' => [
        '此为免费模块，如你是买来的恭喜你被骗了。',
    ],
];
