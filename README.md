# LvccLogin

iOS 15.4.1 / **thin arm64** / TrollStore + TrollFools 环境下的驴充充密码登录注入模块。

## v0.2.0 修复
上一版 CI 用 `find .theos -name "*.dylib"` 收集产物，把
`.theos/obj/iphoneos.arm64/LvccLogin.dylib.dSYM/Contents/Resources/DWARF/LvccLogin.dylib`
一起 cp 进 out/ 并覆盖了真二进制。那个文件 filetype = MH_DSYM(10)，
TrollFools 内置 ldid 不认，直接报 `ldid: Unsupported Mach-O type` / exit 1。

修法：
- ARCHS 改成单 `arm64`（不再输出 fat）
- `-g0` 关调试符号
- CI 排除 dSYM 目录，并硬断言 `otool -hv` 的 filetype 必须是 `DYLIB`，否则 exit 1

## 功能
- 悬浮球 → 手机号 + 密码直接调 `/registerOrLoginUser`（validateType=2, entryType=5）
- 「导出 NSUserDefaults」看 App 把 token 存在哪个 key
- 「导出 Keychain」看是否走钥匙串
- hook `NSUserDefaults set*` / `SecItemAdd|Update`，记录 App 自己的存储写入
- 日志：`/var/mobile/Library/Caches/lvcc_tweak.log`

## 产物
`LvccLogin.dylib` —— thin arm64，MH_DYLIB，已 ldid -S 签名。TrollFools 会重签，无冲突。
