# OhMyKeymint 云端服务端

给 OhMyKeymint 模块提供 keybox 云端分发（含自动吊销校验）与 PIF 指纹聚合下发。
自包含的 PHP，只依赖同目录 `lib/`。

## 目录结构

```
server/
  config.php         配置（base_url / 上游源 / 签名 / 目录）
  update_keybox.php  定时任务：拉取并择优 keybox（含证书链/有效期/吊销校验）
  update_pif.php     定时任务：聚合 PIF 指纹
  update.sh          宝塔计划任务包装
  lib/               http / keybox 校验 / 吊销 / Ed25519 签名 / PIF 聚合
  keys/              Ed25519 密钥（首次运行自动生成，必须在 web 根之外）
  public/            web 根（站点 URL 前缀 /api/omk 指向这里）
    index.php        前端控制器：?action=manifest / ?action=keybox
    pif/             静态指纹 feed（device_list.json + device_prop/*.prop）
    data/              私有数据（web 根之外，只能由 index.php 读取）
    keybox.xml
    manifest.json
    revocation.json
    rotation.json       keybox 轮换池（每个 enabled 源各一份）
    pool/               成员文件（<sha256>.xml）与历史快照
```

职责边界：

- `public/` 是唯一的 web 根。只有 `index.php` 和静态 `pif/` 会被直接访问。
- `data/`、`keys/`、`lib/`、`update_*.php` 全部位于 web 根之外，无法经 URL 访问。
- keybox 与 manifest 不再作为静态文件暴露，客户端只能通过 `index.php?action=`
  读取，服务端因此可以按请求做鉴权/限流/日志扩展。

## 客户端取用契约

| 资源 | URL |
| --- | --- |
| keybox | `<base>/index.php?action=keybox` |
| 第 N 份 keybox（不推进轮换） | `<base>/index.php?action=keybox&offset=N` |
| 清单（sha256 + 签名 + 有效性） | `<base>/index.php?action=manifest` |
| PIF 设备目录 | `<base>/pif/device_list.json` |
| PIF 指定设备指纹 | `<base>/pif/device_prop/<product>.prop` |

`<base>` 即 `config.php` 的 `base_url`，默认 `https://omk.5ijxa.com/api/omk`。

keybox 的完整性由 `manifest.json` 的 `signature` 字段保障：它是用 Ed25519
私钥（`keys/ed25519.key`）对 keybox.xml 原始字节做 detached 签名得到的，
`sign_public` 为对应公钥（base64）。客户端内置了默认站点的公钥作为编译期信任
锚；`config.toml` 的 `server.trusted_keybox_pubkey` 可覆盖它，支持直接粘贴
base64 或 64 位 hex。

## keybox 轮换

服务端从每个 enabled 源各取一份最新有效 keybox，组成轮换池（`data/rotation.json`），
每个成员单独签名并存入 `data/pool/<sha256>.xml`：

- 不再按 `priority` 择优：`update_keybox.php` 每轮把每个 enabled 源的一份有效
  keybox 都收进池子（`github_dir` 型源按自已的按日取样逻辑取一份）。
- `index.php?action=keybox` 每次请求原子地取当前成员并推进一格，按池顺序轮转，
  所以客户端连续申请会依次拿到不同来源的 keybox（池里有 N 份，则第 N+1 次
  申请回到第一份）。
- `index.php?action=keybox&offset=N` 非破坏性取「当前指针之后第 N 个未吊销成员」
  （offset=0 即下一个会下发的成员），**不改动轮换 index**。客户端想再拿一份
  keybox（例如「第二份」）时用 offset=1 即可，不会把所有人的轮换位置推走。
- `index.php?action=manifest` 不推进 index，渲染的是「下一次 action=keybox 会
  下发」的那份的 sha256 / 签名 / 有效性，与 keybox 内容一一对应，客户端签名
  校验契约不变。manifest 的 `keybox.rotation` 还带两份成员级数据：
  - `pool`：按轮换顺序列出的每个未吊销成员的 `source` / `sha256` / `size` /
    `signature` / `validity`，`pool[0]` 恒等于 manifest 里那份 keybox，`pool[N]`
    与 `action=keybox&offset=N` 一一对应；
  - `excluded`：本轮被吊销名单拦截、既不下发也不进 pool 的成员数。
已吊销成员永远不会进 pool、也不会经 `action=keybox` 下发（请求时以手工列表 +
   永久名单 + 最新在线快照做最终拦截）。

## 吊销状态发布与上报阈值

`manifest.json` 的 `keybox.revocation` 段随清单下发当前吊销状态与上报阈值，
供客户端绑定展示（只读透传，客户端不做本地吊销判定）：

- `permanent_count` / `pending_count`：永久名单条数、尚未达阈值的上报数；
- `report_threshold`：在线快照已收录该序列号时，入永久名单所需的上报数；
- `report_unverified_threshold`：序列号不在快照中时的所需上报数（防投毒，默认 10）；
- `checked` / `count` / `source` / `fetched_at` / `fresh`：本轮核对序列号数、
  快照条数、快照来源、抓取时间与新鲜度；
- `sources`：各吊销源本次的成功状态与条目数。

## 云端通告

`config.php` 的 `notice` 数组（字符串列表）会随 manifest 的 `keybox.notice`
字段下发。OMK 客户端在每次获取 keybox 时原样展示这些内容（云端 keybox 弹窗
内常驻提示；成功获取后还会再弹一次），用于传达授权声明、反倒卖提示等。

- `index.php?action=manifest` 每次请求都从 `config.php` 重新注入 `keybox.notice`，
  改配置后立即生效，无需重跑更新脚本。
- `update_keybox.php` 写 manifest 模板时也会带上当前配置的 `notice`，保证旧版本
  客户端拿到的 manifest.json 模板结构完整。
- 空数组表示不下发任何通告。
- 轮换池刷新时机跟随 `update.sh keybox`（默认每天 00:00）。index 在更新时保留，
  不会每次更新都从池头开始。
- 人工固定 keybox（`keybox_pin`，例如 `qianxiaokey.xml`）存在且校验通过时作为
  轮换池第一个成员下发（最优先），不再是「固定唯一交付」；删掉该文件即恢复纯
  上游轮换。

## 环境要求

- PHP 8.x（示例路径 `/www/server/php/84/bin/php`）。
- PHP 扩展：`curl`、`openssl`、`mbstring`、`sodium`（Ed25519 签名必需），
  `json`（PHP 8 默认内置）。
- nginx（或 Apache），需要一个可用的 php-fpm 上游。
- 以 `www` 用户运行更新脚本，使生成文件的属主与 PHP 进程一致。

检查扩展是否齐全：

```sh
/www/server/php/84/bin/php -m | grep -E 'curl|openssl|mbstring|sodium'
```

## 部署步骤

1. 把整个 `server/` 目录放到站点目录下的可写位置，例如
   `/www/wwwroot/omk.5ijxa.com/api/omk/server/`。

2. 在站点（`omk.5ijxa.com`）里把 URL 前缀 `/api/omk` 指向 `server/public/`，
   并让 `index.php` 走 php-fpm。宝塔 nginx 可直接加：

   ```nginx
   # 前端控制器：keybox / manifest
   location = /api/omk/index.php {
       alias /www/wwwroot/omk.5ijxa.com/api/omk/server/public/index.php;
       fastcgi_pass unix:/tmp/php-cgi-84.sock;
       fastcgi_index index.php;
       include fastcgi.conf;
   }

   # 静态 PIF 指纹 feed
   location /api/omk/pif/ {
       alias /www/wwwroot/omk.5ijxa.com/api/omk/server/public/pif/;
       try_files $uri =404;
       autoindex off;
   }

   # 其余 /api/omk/* 一律拒绝，避免暴露内部结构
   location /api/omk/ {
       return 404;
   }
   ```

   `fastcgi_pass` 的值按实际 PHP-FPM 监听方式填写（宝塔通常是
   `unix:/tmp/php-cgi-84.sock`；若为 TCP 则形如 `127.0.0.1:9000`）。

   也可以把站点根直接设为 `server/public/`，此时把 `config.php` 的 `base_url`
   改成站点根地址，并相应调整上面的 location 前缀。

3. 核对 `config.php` 的 `base_url` 与公开访问地址一致（无结尾斜杠）。

4. 首次运行一次 keybox 更新，让服务端生成密钥与数据文件：

   ```sh
   /path/to/server/update.sh keybox
   ```

   运行后 `keys/ed25519.pub`（即 `sign_public`，base64）会被创建。它是客户端
   校验签名所需的公钥。若你要更换默认站点公钥，把该值同步进客户端
   `src/remote_keybox.rs` 的 `TRUSTED_PUBKEY_B64` 并重新编译。

5. 确认 `data/`、`public/` 属主均为 `www`，`keys/` 权限收紧到 `700`。
   `update.sh` 每次运行都会自动修正，无需手工处理。

## 计划任务

宝塔「计划任务」添加两条 Shell 脚本（先按实际路径改 `update.sh` 顶部的
`PHP` 与 `DIR`）：

```sh
# 每天 00:00 更新 keybox
/path/to/server/update.sh keybox

# 每天 02:00 聚合 PIF 指纹
/path/to/server/update.sh pif
```

也可直接写进 crontab（与宝塔等价）：

```cron
0 0 * * * /path/to/server/update.sh keybox
0 2 * * * /path/to/server/update.sh pif
```

日志落盘在 `server/update.log`。

## 上游源

- keybox：`config.php` 的 `sources`（每个 enabled 源各取一份最新有效 keybox，
  轮换下发；`data/rotation.json` 是轮换池，`data/pool/<sha256>.xml` 是成员文件）。
- 吊销名单：`revocation_sources`（GitHub 镜像优先，官方地址兜底）。
- PIF：`pif_sources`，默认 2 个 GitHub 源（Elcapitanoe/PIF-Config-Generator、
  xprateek/PIF-JSON-Generator）。

所有 GitHub 下载都先走加速前缀 `github_accel`（默认 `https://gh-proxy.com/`），
失败再直连；设为空字符串即全程直连。

## 人工固定 / 回滚

放一份 keybox XML 于 `config.php` 的 `keybox_pin` 指定的路径（示例
`server/qianxiaokey.xml`），`update_keybox.php` 在校验通过后把它作为轮换池的
第一个成员（最优先下发），其它上游源依然入池轮换。删除该文件即恢复纯自动轮换。

## 自检

```sh
# 语法检查
php -l config.php
php -l public/index.php
php -l update_keybox.php
php -l update_pif.php

# 手动跑一次并观察日志
/path/to/server/update.sh all
tail -n 50 /path/to/server/update.log
```
