Oh My Keymint-R1 1.3.6 首个发布

基于 ITxiao6666/OhMyKeymint（上游 qwq233/OhMyKeymint）的二改版本，主要变化：

- 统一显示名为 Oh My Keymint-R1-版本-哈希后7位；模块描述开机自检动态回写运行状态
- WebUI 全新透明玻璃主题，支持自定义壁纸，文案本地化
- Soter 相关修复增强，PIF 属性协同与痕迹收敛
- 移除内置中继凭据：中继身份改为完全由用户配置，缺省关闭，开启即校验（fail-closed）
- tag 驱动的自动更新链路：发布包 versionCode 以包内 module.prop 为权威来源
