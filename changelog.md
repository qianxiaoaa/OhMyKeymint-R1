# Changelog

本分支由 release 工作流（update-changelog.yml）自动维护：每次发布 Release 时，
`changelog.md` 会被替换为该 Release 的说明，`update.json` 记录最新版本号与下载地址，
versionCode 以发布包内 module.prop 为权威来源。模块管理器据此判断是否提示更新。

首次发布前，此文件为占位内容。
