# OhMyKeymint-R1 云端服务端

给 OhMyKeymint-R1 模块提供 PIF 指纹聚合下发与在线设备统计。自包含的 PHP，只依赖同目录 `lib/`。

云端不负责 keybox：客户端从固定的 GitHub 社区镜像源自行抓取、校验并安装最新有效 keybox，服务端没有任何 keybox / manifest / 吊销 / 轮换 / 签名逻辑。

## 目录结构

```
server/
  index.html           站点首页（展示在线设备数 + PIF 下发统计）
  scripts/app/stats.js 首页统计轮询（每 3s fetch action=stats）
  api/omk/             后端（站点 URL 前缀 /api/omk 指向本目录的 public/）
    config.php         配置（base_url / PIF 源 / 在线统计窗口）
    update_pif.php     定时任务：聚合 PIF 指纹
    update.sh          宝塔计划任务包装
    lib/               http 下载 / PIF 聚合 / 在线统计 / 下发计数
    public/            web 根
      index.php        前端控制器：?action=stats / ?action=report / ?action=pif
      pif/             静态指纹 feed（device_list.json + device_prop/*.prop，运行时生成）
    data/              私有数据（web 根之外，只能由 index.php 读取）
```

职责边界：

- `public/` 是唯一的 web 根。只有 `index.php` 和静态 `pif/` 会被直接访问。
- `data/`、`lib/`、`update_*.php` 全部位于 web 根之外，无法经 URL 访问。

## 站点接口

| 资源 | URL | 用途 |
| --- | --- | --- |
| 统计 | `<base>/index.php?action=stats` | 在线设备数 + 在线 Keybox 数 + PIF 下发数（首页用） |
| 心跳上报 | `<base>/index.php?action=report` | 客户端每 30 分钟 POST 一次 |
| PIF 设备目录 | `<base>/pif/device_list.json` | 客户端指纹列表 |
| PIF 指定设备指纹 | `<base>/pif/device_prop/<product>.prop` | 客户端指纹下载 |

`<base>` 即 `config.php` 的 `base_url`，默认 `https://omk.5ijxa.com/api/omk`。

## 在线设备统计

客户端（keystore 身份的 OMK 模块）每 `online_interval` 秒向 `action=report` POST：

```json
{ "module_id": "omk-<16..64 lowercase hex>", "keybox_sha256": "<64 hex，可为空>" }
```

- `module_id` 是安装内生成的独立设备号（`omk-` 前缀 + 16..64 个 hex；当前客户端发 32 个），服务端只存储其 SHA-256 前 20 个 hex 作为去重键，不落原始值。
- 超过 `online_window` 秒（默认 6 小时）无心跳的设备自动过期，`stats.devices` 即当前活跃设备数。
- 同一设备两次心跳至少间隔 `online_interval/2` 才续期，防止高频重放无限保活；设备数达到 `online_max_devices` 后不再接受新设备入表。
- `stats.keybox_distinct` 是当前在线设备中不同 `keybox_sha256` 的去重数，反映真实在线设备使用的 Keybox 种类。
- 首页展示的「xxx 台设备」来自真实活跃心跳，可辩护的存活度量，与旧的 keybox 下发计数（无法区分设备）无关。

## 环境要求

- PHP 8.x（示例路径 `/www/server/php/84/bin/php`）。
- PHP 扩展：`curl`、`openssl`、`mbstring`、`json`（PHP 8 默认内置）。
- nginx（或 Apache），需要一个可用的 php-fpm 上游。
- 以 `www` 用户运行更新脚本，使生成文件的属主与 PHP 进程一致。

检查扩展是否齐全：

```sh
/www/server/php/84/bin/php -m | grep -E 'curl|openssl|mbstring'
```

## 部署步骤

1. 把整个 `server/` 目录放到站点目录（vhost 根），例如
   `/www/wwwroot/omk.5ijxa.com/`。首页即 `index.html`，后端位于 `api/omk/`。

2. 把 URL 前缀 `/api/omk` 指向 `api/omk/public/`，并让 `index.php` 走 php-fpm。
   宝塔 nginx 可直接加：

   ```nginx
   # 前端控制器：stats / report
   location = /api/omk/index.php {
       alias /www/wwwroot/omk.5ijxa.com/api/omk/public/index.php;
       fastcgi_pass unix:/tmp/php-cgi-84.sock;
       fastcgi_index index.php;
       include fastcgi.conf;
   }

   # PIF 指纹 feed 经控制器转发并计数
   location /api/omk/pif/ {
       rewrite ^/api/omk/pif/(.*)$ /api/omk/index.php?action=pif&file=$1 last;
   }

   # 其余 /api/omk/* 一律拒绝，避免暴露内部结构
   location /api/omk/ {
       return 404;
   }
   ```

   `fastcgi_pass` 的值按实际 PHP-FPM 监听方式填写（宝塔通常是
   `unix:/tmp/php-cgi-84.sock`；若为 TCP 则形如 `127.0.0.1:9000`）。

3. 核对 `config.php` 的 `base_url` 与公开访问地址一致（无结尾斜杠）。

4. 首次运行一次 PIF 更新，让服务端生成 feed 与数据文件：

   ```sh
   /path/to/server/api/omk/update.sh pif
   ```

5. 确认 `data/`、`public/` 属主均为 `www`。`update.sh` 每次运行都会自动修正。

## 计划任务

宝塔「计划任务」添加一条 Shell 脚本（先按实际路径改 `update.sh` 顶部的
`PHP` 与 `DIR`）：

```sh
# 每天 02:00 聚合 PIF 指纹
/path/to/server/api/omk/update.sh pif
```

也可直接写进 crontab（与宝塔等价）：

```cron
0 2 * * * /path/to/server/api/omk/update.sh pif
```

日志落盘在 `api/omk/update.log`。

## 上游源

- PIF：`config.php` 的 `pif_sources`，默认 2 个 GitHub 源（Elcapitanoe/PIF-Config-Generator、
  xprateek/PIF-JSON-Generator）。

所有 GitHub 下载都先走加速前缀 `github_accel`（默认 `https://gh-proxy.com/`），
失败再直连；设为空字符串即全程直连。

## 自检

```sh
# 语法检查
php -l config.php
php -l public/index.php
php -l update_pif.php
php -l lib/online.php
php -l lib/counter.php

# 手动跑一次并观察日志
/path/to/server/api/omk/update.sh pif
tail -n 50 /path/to/server/api/omk/update.log
```