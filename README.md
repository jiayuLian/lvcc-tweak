# LvccLogin

iOS 15.4.1 / thin arm64 / **零依赖** / TrollStore + TrollFools。

## 版本史

| 版本 | 问题 |
|---|---|
| v0.1.0 | CI 把 dSYM 里的 DWARF 当成 dylib 上传，filetype=MH_DSYM(10)，TrollFools 报 `ldid: Unsupported Mach-O type` |
| v0.2.0 | 产物修对了，但用 theos `tweak.mk`，链接 CydiaSubstrate，未定义 `_MSHookFunction` / `_MSHookMessageEx`。TrollStore 设备没装 ElleKit → App 启动闪退 |
| v0.3.0 | 改 `library.mk` + `__attribute__((constructor))`，不用 logos、不用 MSHook*，外部依赖只剩系统框架 |

## v0.3.0 依赖清单（编译后自动断言）

```
/usr/lib/libobjc.A.dylib
/System/Library/Frameworks/Foundation.framework/Foundation
/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
/System/Library/Frameworks/UIKit.framework/UIKit
/System/Library/Frameworks/Security.framework/Security
/usr/lib/libSystem.B.dylib
```

CI 会 `grep substrate|ellekit` 与 `nm -u | grep _MSHook`，命中即 `exit 1`。

## 功能

- 悬浮球「登」→ 三个动作
- **导出存储**：NSUserDefaults 全量 + Keychain 全量 + 沙盒可疑目录，结果直接弹窗显示并自动复制到剪贴板（不用再找日志文件）
- **手机号+密码登录**：调 `/registerOrLoginUser`（validateType=2, entryType=5）
- **查看日志**：弹窗显示 `/var/mobile/Library/Caches/lvcc_tweak.log` 末尾 200KB

导出结果里会自动标注哪些值像长效凭证：

```
someKey = eyJhbGciOi...     ← JWT ★长效 有效期2592000s sub=5 userId=75555283
otherKey = xxxxxxxx...      ← ★疑似长效串
```

30 秒短票标 `短票`，长有效期标 `★长效` —— 找的就是后者。
