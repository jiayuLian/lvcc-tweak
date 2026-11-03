# LvccLogin

iOS 15.4.1 / arm64 / TrollStore 环境下的驴充充密码登录注入模块。

## 功能
- 悬浮球 → 手机号 + 密码直接调 `/registerOrLoginUser`（validateType=2, entryType=5）
- 全程记录 App 自身的 NSUserDefaults / Keychain 写入，用于定位 token 落盘 key
- 日志：`/var/mobile/Library/Caches/lvcc_tweak.log`

## 编译
push 到 main 即触发 GitHub Actions，产物在 Artifacts → LvccLogin（fat: arm64 + arm64e）。
