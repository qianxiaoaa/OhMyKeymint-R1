Release v1.3.6-108 (commit a10c879)

- 云端状态卡片修复：输出保持结构体键序并净化错误文本
- 清理 mirror/online worker 死代码（Condvar 无触发逻辑移除）
- 构建脚本：delete_old_zips 不再误删旧版本包；deploy_hot_update 修复 x86_64 BoringSSL 构建
- 模板：daemon 刷新描述防并发累积；uninstall/customize 补充注释
- WebUI：inject 命令输出上限、dev 版本号去硬编码、Config stub 注释
- 文档：CONFIGURATION.md 修正 version 章节并补充 [r1] 表，FAQ 修正群链接
