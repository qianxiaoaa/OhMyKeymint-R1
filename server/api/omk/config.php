<?php
/**
 * OhMyKeymint-R1 云端服务端配置。
 *
 * 自包含：只依赖同目录的 lib/。
 *
 * 部署：整个站点（仓库 server/）的 web 根指向仓库 server/ 目录，把 URL 前缀
 * `/api/omk` 指向本文件所在目录的 `public/`。对外只保留三类接口：
 *   <base>/index.php?action=stats   在线设备 + PIF 下发统计（网站首页用）
 *   <base>/index.php?action=report  设备心跳上报（POST，客户端每 30 分钟一次）
 *   <base>/pif/device_list.json     PIF 指纹目录（静态文件）
 *   <base>/pif/device_prop/<product>.prop
 *
 * keybox 不再由云端下发：客户端从固定的 GitHub 社区镜像源自行抓取并校验安装。
 *
 * 结构性说明：
 *   - `public/` 是 web 根。只有 `index.php`（stats/report 前端控制器）和
 *     `pif/`（静态指纹 feed）位于其中，可直接访问。
 *   - `data/`（counter.json / online.json）是私有数据，放在 web 根之外，
 *     只能由 `index.php` 通过 action 参数读取。
 *   - `lib/`、`update_pif.php` 同样在 web 根之外，不会被直接访问。
 */
return [
    // 对客户端可见的基础地址（必须以 http(s):// 开头，无结尾斜杠）
    'base_url' => 'https://omk.5ijxa.com/api/omk',

    // 私有数据目录（counter.json / online.json / cache/，web 根之外）
    'data_dir' => __DIR__ . '/data',

    // 公开的 PIF 指纹 feed 目录（web 根内，静态文件；URL 契约不变）
    'pif_dir' => __DIR__ . '/public/pif',

    'version'      => 'v3.0.0',
    'version_code' => 300,

    // GitHub 加速前缀：github.com 源先走此加速，失败再直连。
    'github_accel' => 'https://gh-proxy.com/',

    // 下载重试次数 / 单次超时秒
    'download_retries' => 3,
    'timeout' => 60,

    // TLS 证书校验。默认开启；只有上游确实使用自签证书时才关闭。
    'http_verify_tls' => true,
    // GitHub contents API 目录列表缓存（秒）；未认证 API 每小时仅 60 次。
    'github_listing_ttl' => 21600,

    // nginx 访问日志：PIF（静态文件）下发计数不能经本控制器统计时靠它兜底；
    // 留空则用 lib/counter.php 内置默认路径 /www/wwwlogs/<站点>.log
    'access_log' => '/www/wwwlogs/omk.5ijxa.com.log',

    // ---- 在线设备统计 ----
    // 客户端每 online_interval 秒上报一次心跳（独立设备号 + 最近安装的
    // keybox SHA-256）。服务端只保留最近 online_window 秒的活动设备为
    // 「正常运行设备数」，超过 online_max_devices 不重复计费。
    'online_interval'    => 1800,   // 客户端心跳间隔（秒），须与客户端一致
    'online_window'      => 21600,  // 在线窗口（秒）＝6 小时
    'online_max_devices' => 200000, // 设备数展示上限（防御性截断）
    // 每个设备的去重标识：字段名固定为 module_id，直接经 TLS 传输，不写日志。
    'online_id_field'    => 'module_id',

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
];