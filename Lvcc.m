// LvccLogin v0.8.0 —— 零依赖版本（无 Substrate / 无 logos / 无 MSHook）
// 目标：iOS 15.4.1 / arm64 / TrollStore + TrollFools
//
// 行为：
//   1) 注入后自动在「登录页」底部浮出一枚橙色胶囊按钮「密码登录」。
//   2) 点按 → 弹出登录卡（手机号 + 密码 + 确定）。
//   3) 确定 → 调密码登录接口(sub=5) 拿到 userToken / refreshToken / userId，
//      按驴充充 App 自己的持久化方式写回：
//        a) NSUserDefaults 一组高频键（双保险）
//        b) 用户态文件 usermodel（逆向确认：UserManager 把 UserModel 序列化到
//           <沙盒目录>/Charge/usermodel，App 启动即读它判定登录态）。
//           v0.8 起按文件真实格式自适应（JSON / 普通 plist / NSKeyedArchiver 归档），
//           并用 App 自己的 UserModel 类参与编解码，避免写坏。
//      随后用 posix_spawn 干净重启 App → 读文件 → 直接进入已登录态（不再硬杀进程）。
//   4) 长按胶囊 → 调试菜单（导出存储 / 查看日志 / 导出 usermodel 文件）。
//
// 关键修复（相对 v0.7.0）：
//   - 写回目录补上 Library/Application Support（之前漏了，导致文件写错位置 → 重进仍要登录）。
//   - 序列化格式自适应：不再盲目按 JSON 写，避免把 NSKeyedArchiver 归档体写坏。
//   - 重启改 posix_spawn 干净重启，消除 exit(0) 造成的「闪退」观感。
//
// 关键修复（相对 v0.8.0）：
//   - 长按调试菜单不再用系统 ActionSheet（半透明遮罩会把登录页底部图标/协议文字透出来显得乱），
//     改为自有全屏不透明遮罩窗口承载菜单与文本查看器，彻底盖住登录页，消除错乱。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <unistd.h>
#import <spawn.h>
#import <string.h>
extern char **environ;

#define BUILD_TAG  @"v0.9.1-arm64-nodep"
#define LOG_PATH   @"/var/mobile/Library/Caches/lvcc_tweak.log"
#define KEYS_PATH  @"/var/mobile/Library/Caches/lvcc_token_keys.plist"
#define API_HOST   @"appapi.lvcchong.com"
#define UA_STR     @"Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
#define ORANGE     [UIColor colorWithRed:1.0f green:0.478f blue:0.0f alpha:1.0f]   // #FF7A00 品牌橙

// ---------------- 日志 ----------------

static void LG(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSLog(@"[LVCC] %@", msg);

    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], msg];
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:LOG_PATH]) {
            [line writeToFile:LOG_PATH atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:LOG_PATH];
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    } @catch (NSException *e) { }
}

static NSString *ReadLogTail(NSUInteger maxBytes) {
    @try {
        NSData *d = [NSData dataWithContentsOfFile:LOG_PATH];
        if (!d) return @"（日志文件不存在）";
        if (d.length > maxBytes) d = [d subdataWithRange:NSMakeRange(d.length - maxBytes, maxBytes)];
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        return s.length ? s : @"（日志为空）";
    } @catch (NSException *e) {
        return @"（读取日志异常）";
    }
}

// ---------------- 工具 ----------------

static NSString *UEnc(NSString *s) {
    if (!s) return @"";
    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
                          @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"];
    return [s stringByAddingPercentEncodingWithAllowedCharacters:ok] ?: s;
}

static NSDictionary *JWTBody(NSString *tok) {
    @try {
        NSArray *parts = [tok componentsSeparatedByString:@"."];
        if (parts.count != 3) return nil;
        NSString *p = parts[1];
        p = [p stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
        p = [p stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
        while (p.length % 4) p = [p stringByAppendingString:@"="];
        NSData *d = [[NSData alloc] initWithBase64EncodedString:p options:0];
        if (!d) return nil;
        return [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    } @catch (NSException *e) {
        return nil;
    }
}

// 返回非空串表示「这个值长得像长效凭证」
static NSString *ClassifyValue(id v) {
    NSString *s = [v description];
    if (![s isKindOfClass:[NSString class]] || s.length < 12) return @"";
    NSDictionary *j = JWTBody(s);
    if (j) {
        double iat = [j[@"iat"] doubleValue], exp = [j[@"exp"] doubleValue];
        if (exp > 0 && iat > 0) {
            double life = exp - iat;
            NSString *kind = life <= 120 ? @"短票" : @"★长效";
            return [NSString stringWithFormat:@"  ← JWT %@ 有效期%.0fs sub=%@ userId=%@",
                    kind, life, j[@"sub"] ?: @"-", j[@"userId"] ?: @"-"];
        }
        return @"  ← JWT";
    }
    if (s.length >= 32) return @"  ← ★疑似长效串";
    return @"";
}

// ---------------- 凭证键自动学习 ----------------

static NSMutableSet   *gNdKeys;   // NSUserDefaults 键名集合
static NSMutableArray *gKcItems;  // Keychain 项：@{@"service":, @"account":}

static void SaveKeys(void) {
    @try {
        NSDictionary *d = @{
            @"nd": [gNdKeys allObjects] ?: @[],
            @"kc": gKcItems ?: @[]
        };
        [d writeToFile:KEYS_PATH atomically:YES];
    } @catch (NSException *e) { }
}

static void LoadKeys(void) {
    gNdKeys = [NSMutableSet set];
    gKcItems = [NSMutableArray array];

    @try {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:KEYS_PATH];
        if (d[@"nd"]) [gNdKeys addObjectsFromArray:d[@"nd"]];
        if (d[@"kc"]) [gKcItems addObjectsFromArray:d[@"kc"]];
    } @catch (NSException *e) { }

    @try {
        NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        for (NSString *k in all) {
            id v = all[k];
            NSString *s = [v isKindOfClass:[NSString class]] ? v : nil;
            if (s.length && ClassifyValue(s).length) [gNdKeys addObject:k];
        }
    } @catch (NSException *e) { }

    @try {
        NSArray *classes = @[(__bridge id)kSecClassGenericPassword,
                             (__bridge id)kSecClassInternetPassword];
        for (id cls in classes) {
            NSDictionary *q = @{
                (__bridge id)kSecClass: cls,
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecReturnData: @YES,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
            };
            CFTypeRef ref = NULL;
            if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref) == errSecSuccess && ref) {
                NSArray *items = (__bridge_transfer NSArray *)ref;
                for (NSDictionary *it in items) {
                    NSData *dat = it[(__bridge id)kSecValueData];
                    NSString *sv = dat ? [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] : nil;
                    if (sv.length && ClassifyValue(sv).length) {
                        [gKcItems addObject:@{
                            @"service": it[(__bridge id)kSecAttrService] ?: @"",
                            @"account": it[(__bridge id)kSecAttrAccount] ?: @""
                        }];
                    }
                }
            }
        }
    } @catch (NSException *e) { }

    SaveKeys();
    LG(@"已学习凭证键: NSUserDefaults=%lu  Keychain=%lu", (unsigned long)gNdKeys.count, (unsigned long)gKcItems.count);
}

static void (*gOrigSetObject)(id, SEL, id, id) = NULL;
static void LVCCSetObject(id self, SEL _cmd, id value, id key) {
    @try {
        NSString *k = [key description];
        NSString *s = [value isKindOfClass:[NSString class]] ? value : nil;
        if (s.length && ClassifyValue(s).length) {
            [gNdKeys addObject:k];
            SaveKeys();
        }
    } @catch (NSException *e) { }
    if (gOrigSetObject) gOrigSetObject(self, _cmd, value, key);
}

static void InstallSetHook(void) {
    @try {
        Method m = class_getInstanceMethod([NSUserDefaults class], @selector(setObject:forKey:));
        if (m) {
            gOrigSetObject = (void(*)(id,SEL,id,id))method_getImplementation(m);
            method_setImplementation(m, (IMP)LVCCSetObject);
        }
    } @catch (NSException *e) { }
}

// 把登录拿到的凭证写回 App 本地存储
static void WriteUserModelFile(NSDictionary *data);   // 前向声明（定义在下方）

// 服务端不同登录分支下发的字段名不统一（微信分支可能给 token/accessToken 而非 userToken）。
// 任一命中即取，避免整组凭证被写空——导出存储实锤 App 读 userToken/token/accessToken 三键同值。
static NSString *PickStr(NSDictionary *d, NSArray *keys) {
    for (NSString *k in keys) {
        id v = d[k];
        if (!v || v == [NSNull null]) continue;
        if (![v isKindOfClass:[NSString class]] && ![v isKindOfClass:[NSNumber class]]) continue;
        NSString *s = [v description];
        if (s.length) return s;
    }
    return @"";
}

static void WriteTokens(NSDictionary *data) {
    @try {
        NSString *ut  = PickStr(data, @[@"userToken", @"token", @"accessToken", @"access_token"]);
        NSString *rt  = PickStr(data, @[@"refreshToken", @"refresh_token"]);
        NSString *uid = PickStr(data, @[@"userId", @"uid", @"user_id"]);
        NSString *mob = PickStr(data, @[@"mobile", @"phone", @"tel"]);
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];

        // 导出存储实锤：App 登录态 = 下面这 7 个键，userToken/token/accessToken 必须同值。
        if (ut.length)  { [ud setObject:ut forKey:@"userToken"]; [ud setObject:ut forKey:@"token"];       [ud setObject:ut forKey:@"accessToken"]; }
        if (rt.length)  { [ud setObject:rt forKey:@"refreshToken"]; }
        if (uid.length) { [ud setObject:uid forKey:@"userId"]; [ud setObject:uid forKey:@"uid"]; }
        if (mob.length) { [ud setObject:mob forKey:@"mobile"]; }

        // App 按 uid_日期 记录登录设备标记，缺失时部分版本会判为「异常设备」要求重登。
        if (uid.length) {
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            [df setDateFormat:@"yyyy-MM-dd"];
            [df setLocale:[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]];
            [ud setObject:[NSString stringWithFormat:@"%@_%@", uid, [df stringFromDate:[NSDate date]]]
                   forKey:@"recordLoginDeviceFlag"];
        }

        LG(@"凭证写回明细: data.keys=%@ | userToken.len=%lu refreshToken.len=%lu userId=%@ mobile=%@",
           [data.allKeys componentsJoinedByString:@","],
           (unsigned long)ut.length, (unsigned long)rt.length, uid, mob);

        // 关键：白名单 7 键写完立刻刷盘。下面 userInfo/Keychain/usermodel 都是兜底逻辑，
        // data 里若含 NSNull 或非 plist 对象，setObject: 会抛异常被外层 @catch 吞掉；
        // 把 synchronize 放最后的话，异常会让凭证停留在内存里，手动杀后台时全部丢失。
        [ud synchronize];

        // v0.9.1：删掉「学到的键」盲写循环。导出存储 140 个键里大量是 TuringShield / 友盟 /
        // OpenUDID 等设备指纹，长度 >=32 会被 ClassifyValue 误判成「疑似凭证」，旧逻辑把它们
        // 全部覆写成 JWT，直接写坏 SDK 缓存 → App 冷启动风控异常 / 判定未登录。
        // 登录态只认上面写死的 7 个白名单键，不再靠「学习」猜。

        @try {
            NSData *jd = [NSJSONSerialization dataWithJSONObject:data options:0 error:nil];
            NSString *js = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : nil;
            if (js.length) {
                [ud setObject:data forKey:@"userInfo"];
                [ud setObject:js   forKey:@"userInfoJson"];
                [ud setObject:js   forKey:@"loginInfo"];
                [ud setObject:js   forKey:@"user"];
            }
        } @catch (NSException *e) { }

        // 凭证已在上文刷盘；此处不再重复 synchronize。

        // Keychain 学到的项
        NSData *val = [ut dataUsingEncoding:NSUTF8StringEncoding] ?: [rt dataUsingEncoding:NSUTF8StringEncoding];
        for (NSDictionary *it in gKcItems) {
            if (!val.length) break;
            NSString *svc = it[@"service"] ?: @"";
            NSString *acct = it[@"account"] ?: @"";
            NSDictionary *q = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrService: svc,
                (__bridge id)kSecAttrAccount: acct
            };
            NSDictionary *upd = @{(__bridge id)kSecValueData: val};
            OSStatus st = SecItemUpdate((__bridge CFDictionaryRef)q, (__bridge CFDictionaryRef)upd);
            if (st != errSecSuccess) {
                NSMutableDictionary *add = [q mutableCopy];
                add[(__bridge id)kSecValueData] = val;
                add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
                SecItemAdd((__bridge CFDictionaryRef)add, NULL);
            }
        }

        // v0.9.1：不再写 usermodel 文件。导出实证该文件只有
        //   {"identificationStatus":1,"isInScreenAd":false}
        // 两个 UI 标志，根本不是凭证载体（v0.6~v0.8 一直往它写 token 是方向性错误）。
        // 往里合并服务端全字段还有被 App 的 Codable 严格解码拒绝的风险，索性原样不动。
        // WriteUserModelFile() 定义保留供导出/诊断，但登录流程不再调用。

        LG(@"凭证已写回：ND键=%lu  KC项=%lu  userToken.len=%lu", (unsigned long)gNdKeys.count, (unsigned long)gKcItems.count, (unsigned long)ut.length);
    } @catch (NSException *e) {
        LG(@"!!! WriteTokens 异常: %@", e.reason);
    }
}

// 逆向确认：UserManager 把 UserModel 存到 <某沙盒目录>/Charge/usermodel。
// 关键修复：
//   1) 搜索目录补上 Library/Application Support（App 用户数据最常用目录，之前漏了）。
//   2) 序列化格式自适应：文件存在时先探测真实格式——
//        - JSON 文本 → 把服务端返回的整个 data 原位合并（含 userToken/refreshToken/userId/mobile 等全部字段），保留其它字段；
//        - 二进制 plist（bplist00）→ 原样用 NSKeyedUnarchiver 解码（App 自己的类参与解码），
//          用 KVC 改 userToken/refreshToken/userId/mobile 后重新归档写回；
//        - 普通 plist 字典 → 同样合并 data 后写回。
//   3) 文件不存在时只在最可信路径新建：先尝试用 App 自己的 UserModel 类构造并归档，
//      失败退回 JSON（写入服务端原始 data）。同时自动创建缺失的中间目录。
static void WriteUserModelFile(NSDictionary *data) {
    @try {
        NSArray *baseDirs = @[
            [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject],
            [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) firstObject],
            [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject],
            [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject],
        ];
        NSArray *relPaths = @[@"Charge/usermodel", @"usermodel", @"Charge/userModel", @"userModel",
                             @"Charge/UserModel", @"UserModel"];
        NSString *ut  = [data[@"userToken"]   description] ?: @"";
        NSString *rt  = [data[@"refreshToken"] description] ?: @"";
        NSString *uid = [data[@"userId"]      description] ?: @"";
        NSString *mob = [data[@"mobile"]      description] ?: @"";

        for (NSString *base in baseDirs) {
            if (![base length]) continue;
            for (NSString *rel in relPaths) {
                NSString *p = [base stringByAppendingPathComponent:rel];
                NSData *existing = [NSData dataWithContentsOfFile:p options:0 error:nil];
                BOOL exists = (existing != nil);

                if (exists) {
                    // ---- 探测真实格式并原位更新 ----
                    NSString *fmt = @"?";
                    BOOL wrote = NO;

                    // 1) JSON
                    if (!wrote) {
                        @try {
                            NSMutableDictionary *m = [[NSJSONSerialization JSONObjectWithData:existing
                                                options:NSJSONReadingMutableContainers error:nil] mutableCopy];
                            if ([m isKindOfClass:[NSMutableDictionary class]]) {
                                [m addEntriesFromDictionary:data];   // 整包覆盖服务端返回字段，保留其余
                                NSError *e = nil;
                                NSData *out = [NSJSONSerialization dataWithJSONObject:m
                                                        options:NSJSONWritingPrettyPrinted error:&e];
                                if (out && [out writeToFile:p atomically:YES]) { fmt = @"JSON"; wrote = YES; }
                                else LG(@"!!! UserModel JSON 写回失败 %@ : %@", p, e.localizedDescription);
                            }
                        } @catch (NSException *ex) { }
                    }

                    // 2) 二进制 plist（可能是 NSKeyedArchiver 归档体，也可能是普通 plist）
                    if (!wrote && existing.length >= 8 && memcmp(existing.bytes, "bplist00", 8) == 0) {
                        // 2a) 普通 plist 字典
                        @try {
                            NSMutableDictionary *m = [[NSPropertyListSerialization
                                propertyListWithData:existing options:NSPropertyListMutableContainers
                                format:nil error:nil] mutableCopy];
                            if ([m isKindOfClass:[NSMutableDictionary class]]) {
                                [m addEntriesFromDictionary:data];
                                if ([m writeToFile:p atomically:YES]) { fmt = @"plist-dict"; wrote = YES; }
                            }
                        } @catch (NSException *ex) { }
                        // 2b) NSKeyedArchiver 归档：用 App 自己的类解码，KVC 改字段后重新归档
                        if (!wrote) {
                            @try {
                                NSError *err = nil;
                                NSKeyedUnarchiver *ua = [[NSKeyedUnarchiver alloc] initForReadingFromData:existing
                                                                       error:&err];
                                ua.requiresSecureCoding = NO;
                                id root = nil;
                                if (ua) {
                                    root = [ua decodeTopLevelObjectForKey:NSKeyedArchiveRootObjectKey error:&err];
                                    [ua finishDecoding];
                                }
                                if (root) {
                                    if (ut.length)  { @try { [root setValue:ut  forKey:@"userToken"]; } @catch (NSException *e) {} }
                                    if (rt.length)  { @try { [root setValue:rt  forKey:@"refreshToken"]; } @catch (NSException *e) {} }
                                    if (uid.length) { @try { [root setValue:uid forKey:@"userId"]; } @catch (NSException *e) {} }
                                    if (mob.length) { @try { [root setValue:mob forKey:@"mobile"]; } @catch (NSException *e) {} }
                                    NSKeyedArchiver *ka = [[NSKeyedArchiver alloc] initRequiringSecureCoding:NO];
                                    [ka encodeRootObject:root];
                                    NSData *arc = [ka encodedData];
                                    [ka finishEncoding];
                                    if (arc && [arc writeToFile:p atomically:YES]) { fmt = @"nskeyed-archive"; wrote = YES; }
                                    else LG(@"!!! UserModel 归档写回失败 %@ : 编码为 nil", p);
                                } else {
                                    LG(@"!!! UserModel NSKeyedUnarchiver 解码为 nil %@ : %@", p, err.localizedDescription);
                                }
                            } @catch (NSException *ex) {
                                LG(@"!!! UserModel NSKeyed 解码异常 %@ : %@", p, ex.reason);
                            }
                        }
                    }

                    if (wrote) LG(@"已更新 UserModel 文件(格式=%@): %@", fmt, p);
                    else      LG(@"!!! UserModel 文件格式无法识别，跳过: %@", p);

                } else {
                    // ---- 文件不存在：只在最可信路径新建 ----
                    if (![rel isEqualToString:@"Charge/usermodel"]) continue;

                    // 确保中间目录存在
                    NSString *dir = [p stringByDeletingLastPathComponent];
                    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                             withIntermediateDirectories:YES attributes:nil error:nil];

                    BOOL wrote = NO;
                    // 尝试用 App 自己的 UserModel 类构造并归档
                    Class umCls = NSClassFromString(@"_TtC6Charge9UserModel");
                    if (umCls) {
                        @try {
                            id model = [[umCls alloc] init];
                            if (model) {
                                if (ut.length)  { @try { [model setValue:ut  forKey:@"userToken"]; } @catch (NSException *e) {} }
                                if (rt.length)  { @try { [model setValue:rt  forKey:@"refreshToken"]; } @catch (NSException *e) {} }
                                if (uid.length) { @try { [model setValue:uid forKey:@"userId"]; } @catch (NSException *e) {} }
                                if (mob.length) { @try { [model setValue:mob forKey:@"mobile"]; } @catch (NSException *e) {} }
                                NSError *e = nil;
                                NSData *arc = [NSKeyedArchiver archivedDataWithRootObject:model
                                                                 requiringSecureCoding:NO error:&e];
                                if (arc && [arc writeToFile:p atomically:YES]) { wrote = YES; LG(@"已新建 UserModel(用App类归档): %@", p); }
                            }
                        } @catch (NSException *ex) { }
                    }
                    // 退回：直接写服务端返回的 JSON
                    if (!wrote) {
                        @try {
                            NSError *e = nil;
                            NSData *out = [NSJSONSerialization dataWithJSONObject:data
                                                            options:NSJSONWritingPrettyPrinted error:&e];
                            if (out && [out writeToFile:p atomically:YES]) {
                                wrote = YES;
                                LG(@"已新建 UserModel(JSON回退): %@", p);
                            } else LG(@"!!! UserModel JSON 新建失败 %@ : %@", p, e.localizedDescription);
                        } @catch (NSException *ex) { }
                    }
                }
            }
        }
    } @catch (NSException *e) {
        LG(@"!!! WriteUserModelFile 异常: %@", e.reason);
    }
}

// 干净重启 App：用 posix_spawn 拉起当前可执行文件的新实例，再退出当前进程。
// 这样不会触发系统「已关闭」的崩溃报告，用户看到的是正常重启而非闪退。
static void RelaunchApp(void) {
    @try {
        NSString *exe = [[NSBundle mainBundle] executablePath];
        if (!exe.length) { LG(@"!!! 取不到可执行路径，退回 exit"); exit(0); }
        pid_t pid = 0;
        char *args[] = { (char *)[exe UTF8String], NULL };
        int rc = posix_spawn(&pid, [exe UTF8String], NULL, NULL, args, environ);
        if (rc == 0) {
            LG(@"posix_spawn 新实例 pid=%d，准备退出当前进程", (int)pid);
        } else {
            LG(@"!!! posix_spawn 失败 rc=%d，退回 exit", rc);
        }
    } @catch (NSException *e) {
        LG(@"!!! RelaunchApp 异常: %@", e.reason);
    }
    exit(0);
}

// 在候选路径里找已存在的 usermodel 文件，返回内容字符串
static NSString *ReadUserModelFiles(void) {
    NSMutableString *out = [NSMutableString string];
    @try {
        NSArray *baseDirs = @[
            [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject],
            [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) firstObject],
            [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject],
            [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject],
        ];
        NSArray *relPaths = @[@"Charge/usermodel", @"usermodel", @"Charge/userModel", @"userModel",
                             @"Charge/UserModel", @"UserModel"];
        BOOL found = NO;
        for (NSString *base in baseDirs) {
            if (![base length]) continue;
            for (NSString *rel in relPaths) {
                NSString *p = [base stringByAppendingPathComponent:rel];
                NSData *d = [NSData dataWithContentsOfFile:p options:0 error:nil];
                if (!d) continue;
                found = YES;
                [out appendFormat:@"\n--- %@ ---\n", p];
                NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                if (!s) {
                    // 二进制 plist（可能是 NSKeyedArchiver 归档）：尽量转成可读字典
                    @try {
                        id pl = [NSPropertyListSerialization propertyListWithData:d
                                    options:NSPropertyListImmutable format:nil error:nil];
                        if ([pl isKindOfClass:[NSDictionary class]]) {
                            NSMutableString *ms = [NSMutableString string];
                            for (NSString *k in pl) {
                                id v = pl[k];
                                NSString *vs = [v isKindOfClass:[NSString class]] ? v : [v description];
                                if (vs.length > 300) vs = [[vs substringToIndex:300] stringByAppendingString:@"…(截断)"];
                                [ms appendFormat:@"  %@ = %@%@\n", k, vs, ClassifyValue(v)];
                            }
                            s = ms;
                        } else {
                            s = [NSString stringWithFormat:@"<二进制 plist，类型 %@>", NSStringFromClass([pl class])];
                        }
                    } @catch (NSException *e) {
                        s = @"<二进制，无法解析>";
                    }
                }
                if (s.length > 4000) s = [[s substringToIndex:4000] stringByAppendingString:@"…(截断)"];
                [out appendString:s];
            }
        }
        if (!found) [out appendString:@"（未在任何候选路径找到 usermodel 文件——说明当前为登出态且尚未创建）"];
    } @catch (NSException *e) {
        [out appendFormat:@"\n读取异常: %@", e.reason];
    }
    return out;
}

// ---------------- HTTP ----------------

static void PostForm(NSString *path, NSDictionary *form, NSString *token, void (^cb)(NSDictionary *)) {
    NSMutableArray *pairs = [NSMutableArray array];
    for (NSString *k in form.allKeys) {
        [pairs addObject:[NSString stringWithFormat:@"%@=%@", UEnc(k), UEnc([form[k] description])]];
    }
    NSString *bodyStr = [pairs componentsJoinedByString:@"&"];

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"https://%@%@", API_HOST, path]];
    if (!url) { cb(nil); return; }

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"https://h5.lvcchong.com/" forHTTPHeaderField:@"Referer"];
    [req setValue:@"https://h5.lvcchong.com" forHTTPHeaderField:@"Origin"];
    [req setValue:UA_STR forHTTPHeaderField:@"User-Agent"];
    [req setValue:(token ?: @"") forHTTPHeaderField:@"token"];
    req.HTTPBody = [bodyStr dataUsingEncoding:NSUTF8StringEncoding];

    LG(@">>> POST %@  body=%@", path, bodyStr);

    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) {
            LG(@"!!! %@ 网络错误: %@", path, err.localizedDescription);
            cb(nil);
            return;
        }
        NSDictionary *j = nil;
        @try { j = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil]; } @catch (NSException *e) { }
        NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
        LG(@"<<< %@  status=%ld  body=%@", path,
           (long)((NSHTTPURLResponse *)resp).statusCode,
           raw.length > 12000 ? [raw substringToIndex:12000] : raw);
        cb(j);
    }];
    [t resume];
}

// ---------------- 登录卡 UI ----------------

// LvccPanel 接口前置，让 LvccLoginVC 能直接调用 dismissLogin（避免 forward declaration 调方法报错）
@interface LvccPanel : NSObject
@property (nonatomic, strong) UIWindow *pillWindow;
@property (nonatomic, strong) UIWindow *loginWindow;
@property (nonatomic, strong) UIButton *pill;
@property (nonatomic, weak)   UIViewController *hostVC;
@property (nonatomic, copy)   NSString *lastText;
@property (nonatomic, strong) UIWindow *debugWindow;
@property (nonatomic, weak)   UIView   *debugCardView;
+ (instancetype)shared;
- (void)installPill;
- (void)startVisibilityMonitor;
- (void)copyLastText;
- (void)dismissLogin;
@end

@interface LvccLoginVC : UIViewController
@property (nonatomic, weak)   LvccPanel *panel;
@property (nonatomic, strong) UITextField *phoneF;
@property (nonatomic, strong) UITextField *pwdF;
@property (nonatomic, strong) UIButton *okBtn;
@property (nonatomic, strong) UILabel  *errLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spin;
@property (nonatomic, strong) UIView  *cardView;
@property (nonatomic, strong) NSLayoutConstraint *centerYCon;   // 卡片垂直居中约束，键盘弹出时改 constant 上移
@end

@implementation LvccLoginVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.45];

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onDimTap:)];
    tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:tap];

    CGFloat cardW = MIN(self.view.bounds.size.width - 40, 340);
    UIView *card = [[UIView alloc] init];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor systemBackgroundColor];
    card.layer.cornerRadius = 18;
    card.layer.shadowColor = [UIColor blackColor].CGColor;
    card.layer.shadowOpacity = 0.25; card.layer.shadowRadius = 16; card.layer.shadowOffset = CGSizeMake(0, 8);
    card.userInteractionEnabled = YES;
    [self.view addSubview:card];

    UIView *header = [[UIView alloc] init];
    header.translatesAutoresizingMaskIntoConstraints = NO;
    header.layer.cornerRadius = 18;
    header.layer.maskedCorners = kCALayerMinXMinYCorner | kCALayerMaxXMinYCorner;
    header.clipsToBounds = YES;
    [card addSubview:header];
    CAGradientLayer *gl = [CAGradientLayer layer];
    gl.colors = @[(__bridge id)ORANGE.CGColor, (__bridge id)[UIColor colorWithRed:1.0 green:0.6 blue:0.2 alpha:1].CGColor];
    gl.startPoint = CGPointMake(0, 0); gl.endPoint = CGPointMake(1, 0);
    [header.layer addSublayer:gl];
    header.layer.needsDisplayOnBoundsChange = YES;

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"密码登录";
    title.font = [UIFont boldSystemFontOfSize:20];
    title.textColor = [UIColor whiteColor];
    [header addSubview:title];

    UILabel *sub = [[UILabel alloc] init];
    sub.translatesAutoresizingMaskIntoConstraints = NO;
    sub.text = @"输入手机号和密码，直接进入 App";
    sub.font = [UIFont systemFontOfSize:12];
    sub.textColor = [UIColor colorWithWhite:1.0 alpha:0.9];
    [header addSubview:sub];

    self.phoneF = [self makeField:@"手机号" secure:NO number:YES];
    self.pwdF   = [self makeField:@"密码（8-20 位，含字母数字）" secure:YES number:NO];

    self.errLabel = [[UILabel alloc] init];
    self.errLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.errLabel.font = [UIFont systemFontOfSize:12];
    self.errLabel.textColor = [UIColor systemRedColor];
    self.errLabel.numberOfLines = 0;
    self.errLabel.text = @"";

    self.okBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    self.okBtn.translatesAutoresizingMaskIntoConstraints = NO;
    self.okBtn.layer.cornerRadius = 12;
    self.okBtn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    [self.okBtn setTitle:@"确 定" forState:UIControlStateNormal];
    [self.okBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [self.okBtn setBackgroundImage:[self imageFromColor:ORANGE] forState:UIControlStateNormal];
    [self.okBtn setBackgroundImage:[self imageFromColor:[UIColor colorWithRed:0.8 green:0.38 blue:0 alpha:1]] forState:UIControlStateHighlighted];
    [self.okBtn addTarget:self action:@selector(onOK) forControlEvents:UIControlEventTouchUpInside];

    UIButton *cancel = [UIButton buttonWithType:UIButtonTypeSystem];
    cancel.translatesAutoresizingMaskIntoConstraints = NO;
    cancel.titleLabel.font = [UIFont systemFontOfSize:16];
    [cancel setTitle:@"取 消" forState:UIControlStateNormal];
    [cancel addTarget:self action:@selector(onCancel) forControlEvents:UIControlEventTouchUpInside];

    // 右上角 × 关闭按钮（醒目，点它或点暗色背景都能关）
    UIButton *xbtn = [UIButton buttonWithType:UIButtonTypeCustom];
    xbtn.translatesAutoresizingMaskIntoConstraints = NO;
    [xbtn setTitle:@"✕" forState:UIControlStateNormal];
    xbtn.titleLabel.font = [UIFont systemFontOfSize:24 weight:UIFontWeightBold];
    [xbtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [xbtn addTarget:self action:@selector(onCancel) forControlEvents:UIControlEventTouchUpInside];
    [header addSubview:xbtn];

    [card addSubview:self.phoneF];
    self.cardView = card;
    [card addSubview:self.pwdF];
    [card addSubview:self.errLabel];
    [card addSubview:self.okBtn];
    [card addSubview:cancel];

    UILayoutGuide *cg = card.layoutMarginsGuide;

    self.centerYCon = [card.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor];
    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        self.centerYCon,
        [card.widthAnchor constraintEqualToConstant:cardW],

        [header.topAnchor constraintEqualToAnchor:card.topAnchor],
        [header.leadingAnchor constraintEqualToAnchor:card.leadingAnchor],
        [header.trailingAnchor constraintEqualToAnchor:card.trailingAnchor],
        [header.heightAnchor constraintEqualToConstant:64],

        [title.topAnchor constraintEqualToAnchor:header.topAnchor constant:12],
        [title.leadingAnchor constraintEqualToAnchor:header.leadingAnchor constant:16],
        [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:3],
        [sub.leadingAnchor constraintEqualToAnchor:header.leadingAnchor constant:16],
        [sub.trailingAnchor constraintLessThanOrEqualToAnchor:xbtn.leadingAnchor constant:-8],

        [xbtn.trailingAnchor constraintEqualToAnchor:header.trailingAnchor constant:-10],
        [xbtn.centerYAnchor constraintEqualToAnchor:header.centerYAnchor],
        [xbtn.widthAnchor constraintEqualToConstant:34],
        [xbtn.heightAnchor constraintEqualToConstant:34],

        [self.phoneF.topAnchor constraintEqualToAnchor:header.bottomAnchor constant:18],
        [self.phoneF.leadingAnchor constraintEqualToAnchor:cg.leadingAnchor],
        [self.phoneF.trailingAnchor constraintEqualToAnchor:cg.trailingAnchor],
        [self.phoneF.heightAnchor constraintEqualToConstant:46],

        [self.pwdF.topAnchor constraintEqualToAnchor:self.phoneF.bottomAnchor constant:12],
        [self.pwdF.leadingAnchor constraintEqualToAnchor:cg.leadingAnchor],
        [self.pwdF.trailingAnchor constraintEqualToAnchor:cg.trailingAnchor],
        [self.pwdF.heightAnchor constraintEqualToConstant:46],

        [self.errLabel.topAnchor constraintEqualToAnchor:self.pwdF.bottomAnchor constant:8],
        [self.errLabel.leadingAnchor constraintEqualToAnchor:cg.leadingAnchor],
        [self.errLabel.trailingAnchor constraintEqualToAnchor:cg.trailingAnchor],

        [self.okBtn.topAnchor constraintEqualToAnchor:self.errLabel.bottomAnchor constant:10],
        [self.okBtn.leadingAnchor constraintEqualToAnchor:cg.leadingAnchor],
        [self.okBtn.trailingAnchor constraintEqualToAnchor:cg.trailingAnchor],
        [self.okBtn.heightAnchor constraintEqualToConstant:48],

        [cancel.topAnchor constraintEqualToAnchor:self.okBtn.bottomAnchor constant:8],
        [cancel.leadingAnchor constraintEqualToAnchor:cg.leadingAnchor],
        [cancel.trailingAnchor constraintEqualToAnchor:cg.trailingAnchor],
        [cancel.heightAnchor constraintEqualToConstant:40],
        [cancel.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14],
    ]];

    dispatch_async(dispatch_get_main_queue(), ^{
        gl.frame = header.bounds;
    });

    // 键盘监听：弹起时把卡片整体上移，避免输入框/确定按钮被键盘盖住
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(keyboardWillShow:)
                                                 name:UIKeyboardWillShowNotification
                                               object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(keyboardWillHide:)
                                                 name:UIKeyboardWillHideNotification
                                               object:nil];
}

- (UITextField *)makeField:(NSString *)placeholder secure:(BOOL)secure number:(BOOL)number {
    UITextField *tf = [[UITextField alloc] init];
    tf.translatesAutoresizingMaskIntoConstraints = NO;
    tf.placeholder = placeholder;
    tf.secureTextEntry = secure;
    tf.keyboardType = number ? UIKeyboardTypeNumberPad : UIKeyboardTypeDefault;
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.backgroundColor = [UIColor secondarySystemBackgroundColor];
    tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    tf.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 10, 10)];
    tf.leftViewMode = UITextFieldViewModeAlways;
    tf.font = [UIFont systemFontOfSize:15];
    return tf;
}

- (UIImage *)imageFromColor:(UIColor *)c {
    UIGraphicsImageRenderer *r = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(1, 1)];
    return [r imageWithActions:^(UIGraphicsImageRendererContext * _Nonnull ctx) {
        [c setFill]; [ctx fillRect:CGRectMake(0, 0, 1, 1)];
    }];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self.phoneF becomeFirstResponder];
}

// 键盘弹起：卡片整体上移半个键盘高，使卡片底部落在键盘顶之上
- (void)keyboardWillShow:(NSNotification *)n {
    NSDictionary *info = n.userInfo;
    CGRect fr = [info[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    CGFloat kbH = fr.size.height;
    CGFloat dur = [info[UIKeyboardAnimationDurationUserInfoKey] doubleValue];
    if (dur <= 0) dur = 0.25;
    self.centerYCon.constant = -kbH / 2.0;
    [UIView animateWithDuration:dur
                          delay:0
                        options:UIViewAnimationOptionCurveEaseInOut
                     animations:^{ [self.view layoutIfNeeded]; }
                     completion:nil];
}

- (void)keyboardWillHide:(NSNotification *)n {
    NSDictionary *info = n.userInfo;
    CGFloat dur = [info[UIKeyboardAnimationDurationUserInfoKey] doubleValue];
    if (dur <= 0) dur = 0.25;
    self.centerYCon.constant = 0;
    [UIView animateWithDuration:dur
                          delay:0
                        options:UIViewAnimationOptionCurveEaseInOut
                     animations:^{ [self.view layoutIfNeeded]; }
                     completion:nil];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)onDimTap:(UITapGestureRecognizer *)g {
    CGPoint p = [g locationInView:self.view];
    if (self.cardView && CGRectContainsPoint(self.cardView.frame, p)) return;
    [self.panel dismissLogin];
}

- (void)onCancel {
    [self.panel dismissLogin];
}

- (void)onOK {
    NSString *phone = [self.phoneF.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *pwd   = [self.pwdF.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (phone.length != 11 || ![phone hasPrefix:@"1"]) {
        self.errLabel.text = @"手机号格式不对（应为 11 位、1 开头）";
        return;
    }
    if (pwd.length < 8 || pwd.length > 20) {
        self.errLabel.text = @"密码需 8-20 位";
        return;
    }
    self.errLabel.text = @"";
    self.okBtn.enabled = NO;
    [self.okBtn setTitle:@"登录中…" forState:UIControlStateNormal];
    if (!self.spin) {
        self.spin = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
        self.spin.color = [UIColor whiteColor];
    }

    NSDictionary *form = @{
        @"mobile": phone,
        @"validateType": @"2",   // 密码登录
        @"password": pwd,
        @"entryType": @"5",
        @"registerOrBind": @"1",
        @"ownerId": @"0",
        @"willingnessToChargeInsurance": @"0",
        @"vsersion": @"1"
    };

    __weak typeof(self) ws = self;
    PostForm(@"/registerOrLoginUser", form, nil, ^(NSDictionary *j) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!j) {
                ws.errLabel.text = @"网络错误，请检查网络后重试";
                [ws resetOK];
                return;
            }
            if ([j[@"code"] integerValue] != 200) {
                NSString *m = j[@"message"] ?: j[@"msg"] ?: @"未知错误";
                ws.errLabel.text = [NSString stringWithFormat:@"登录失败：%@", m];
                [ws resetOK];
                return;
            }
            // 防服务端把 data 下成字符串/数组：类型不对就当空，避免 allKeys 抛异常把整个回调打断。
            NSDictionary *d = ([j[@"data"] isKindOfClass:[NSDictionary class]]) ? j[@"data"] : @{};
            LG(@"登录响应 code=%@ success=%@ data.keys=%@",
               j[@"code"], j[@"success"], [d.allKeys componentsJoinedByString:@","]);
            WriteTokens(d);
            [ws showSuccessThenGuide];
        });
    });
}

- (void)resetOK {
    self.okBtn.enabled = YES;
    [self.okBtn setTitle:@"确 定" forState:UIControlStateNormal];
}

- (void)showSuccessThenGuide {
    for (UIView *v in self.view.subviews) v.hidden = YES;
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    // v0.9.1：取消自动重启。iOS 禁止同一 bundle 双实例，posix_spawn 拉起的第二个实例会被
    // SpringBoard 立即强杀，表现就是「点确定 → 闪退 → 重开仍停在登录页」。凭证已落盘，
    // 交给用户手动冷启动：App 才会真正重新读一遍 NSUserDefaults，也把「重启」这个变量摘掉。
    UIImageView *check = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"checkmark.circle.fill"]];
    check.tintColor = [UIColor systemGreenColor];
    check.translatesAutoresizingMaskIntoConstraints = NO;
    check.contentMode = UIViewContentModeScaleAspectFit;
    [self.view addSubview:check];

    UILabel *t1 = [[UILabel alloc] init];
    t1.translatesAutoresizingMaskIntoConstraints = NO;
    t1.text = @"登录成功";
    t1.font = [UIFont boldSystemFontOfSize:24];
    t1.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:t1];

    UILabel *t2 = [[UILabel alloc] init];
    t2.translatesAutoresizingMaskIntoConstraints = NO;
    t2.text = @"凭证已写入。请立刻上划杀掉 App 后台，再重新打开即可进入已登录状态。\n（短票有效期 30 秒，别隔太久再开）";
    t2.font = [UIFont systemFontOfSize:14];
    t2.textColor = [UIColor secondaryLabelColor];
    t2.textAlignment = NSTextAlignmentCenter;
    t2.numberOfLines = 0;
    [self.view addSubview:t2];

    UIButton *rb = [UIButton buttonWithType:UIButtonTypeSystem];
    rb.translatesAutoresizingMaskIntoConstraints = NO;
    [rb setTitle:@"仍要自动重启（实验）" forState:UIControlStateNormal];
    rb.titleLabel.font = [UIFont systemFontOfSize:13];
    [rb addTarget:self action:@selector(onTryRelaunch) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:rb];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [check.widthAnchor constraintEqualToConstant:72], [check.heightAnchor constraintEqualToConstant:72],
        [check.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [check.centerYAnchor constraintEqualToAnchor:g.centerYAnchor constant:-60],
        [t1.topAnchor constraintEqualToAnchor:check.bottomAnchor constant:16],
        [t1.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [t2.topAnchor constraintEqualToAnchor:t1.bottomAnchor constant:10],
        [t2.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [t2.widthAnchor constraintEqualToConstant:300],
        [rb.topAnchor constraintEqualToAnchor:t2.bottomAnchor constant:18],
        [rb.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
    ]];

    LG(@"登录成功：凭证已写入 NSUserDefaults，等待用户手动冷启动（不自动重启，避免双实例强杀）");
}

- (void)onTryRelaunch {
    LG(@"用户选择实验性自动重启（posix_spawn，可能被 SpringBoard 强杀）");
    RelaunchApp();
}

@end

// ---------------- 胶囊按钮 + 面板 ----------------

@implementation LvccPanel

+ (instancetype)shared {
    static LvccPanel *o;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ o = [[LvccPanel alloc] init]; });
    return o;
}

- (UIWindowScene *)activeScene {
    @try {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) {
                UIWindowScene *ws = (UIWindowScene *)s;
                if (ws.activationState == UISceneActivationStateForegroundActive ||
                    ws.activationState == UISceneActivationStateForegroundInactive) {
                    return ws;
                }
            }
        }
    } @catch (NSException *e) { }
    return nil;
}

// ★修复：iOS13+ 场景化 App 下 UIApplication.windows 常为空，
//   必须从 UIWindowScene.windows 取 keyWindow，否则按钮/弹窗全失效。
- (UIWindow *)keyWindow {
    @try {
        UIWindowScene *scene = [self activeScene];
        if (scene) {
            for (UIWindow *w in scene.windows) {
                if (w.isKeyWindow) return w;
            }
            for (UIWindow *w in scene.windows) {
                if (w.rootViewController) return w;
            }
            if (scene.windows.firstObject) return scene.windows.firstObject;
        }
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w.isKeyWindow) return w;
        }
        return UIApplication.sharedApplication.windows.firstObject;
    } @catch (NSException *e) { }
    return nil;
}

- (UIViewController *)topVC {
    @try {
        UIWindow *key = [self keyWindow];
        UIViewController *vc = key.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        return vc;
    } @catch (NSException *e) {
        return nil;
    }
}

// 递归扫描视图：是否含输入框 + 登录类按钮（含 attributedTitle）
static void LVCCScanView(UIView *v, BOOL *hasTF, BOOL *hasLoginBtn) {
    for (UIView *sub in v.subviews) {
        if ([sub isKindOfClass:[UITextField class]] || [sub isKindOfClass:[UITextView class]]) *hasTF = YES;
        if ([sub isKindOfClass:[UIButton class]]) {
            UIButton *b = (UIButton *)sub;
            NSString *t = [b titleForState:UIControlStateNormal];
            if (!t) t = [b titleForState:UIControlStateSelected];
            if (!t) {
                NSAttributedString *at = [b attributedTitleForState:UIControlStateNormal];
                if (!at) at = [b attributedTitleForState:UIControlStateSelected];
                t = at.string;
            }
            if (t && ([t containsString:@"登录"] || [t containsString:@"手机号"] ||
                     [t containsString:@"微信"] || [t containsString:@"Apple"] ||
                     [t containsString:@"验证码"] || [t containsString:@"注册"])) *hasLoginBtn = YES;
        }
        LVCCScanView(sub, hasTF, hasLoginBtn);
    }
}

// 判定 VC 是否为登录页：
//   优先按类名含 "Login"（Swift/SwiftUI 页面按文字扫描会漏，最稳）；
//   其次回退到「有输入框 + 登录类按钮」的视图扫描。
static BOOL VCLooksLikeLogin(UIViewController *vc) {
    if (!vc) return NO;
    NSString *cn = NSStringFromClass([vc class]);
    if ([cn rangeOfString:@"Login" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    if (!vc.isViewLoaded || !vc.view) return NO;
    BOOL hasTF = NO, hasLoginBtn = NO;
    LVCCScanView(vc.view, &hasTF, &hasLoginBtn);
    return hasTF && hasLoginBtn;
}

- (UIViewController *)findLoginVC {
    @try {
        UIWindow *key = [self keyWindow];
        UIViewController *root = key.rootViewController;
        if (!root) return nil;
        NSMutableArray *stack = [NSMutableArray arrayWithObject:root];
        while (stack.count) {
            UIViewController *vc = stack.lastObject;
            [stack removeLastObject];
            if (VCLooksLikeLogin(vc)) return vc;
            [stack addObjectsFromArray:vc.childViewControllers];
            if (vc.presentedViewController) [stack addObject:vc.presentedViewController];
        }
    } @catch (NSException *e) { }
    return nil;
}

- (void)installPill {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (self.pillWindow) { self.pillWindow.hidden = NO; [self startVisibilityMonitor]; return; }

            UIWindowScene *scene = [self activeScene];
            UIWindow *w = scene ? [[UIWindow alloc] initWithWindowScene:scene]
                                : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
            CGRect sr = UIScreen.mainScreen.bounds;
            CGFloat ww = 200, wh = 84;
            w.frame = CGRectMake((sr.size.width - ww) / 2.0,
                                 sr.size.height - wh - 40, ww, wh);
            w.windowLevel = UIWindowLevelAlert + 1000;
            w.backgroundColor = [UIColor clearColor];
            w.rootViewController = [[UIViewController alloc] init];
            w.rootViewController.view.backgroundColor = [UIColor clearColor];
            w.hidden = YES;
            w.alpha = 0;
            self.pillWindow = w;

            UIButton *pill = [UIButton buttonWithType:UIButtonTypeCustom];
            pill.translatesAutoresizingMaskIntoConstraints = NO;
            pill.layer.cornerRadius = 22;
            pill.layer.shadowColor = [UIColor blackColor].CGColor;
            pill.layer.shadowOpacity = 0.35; pill.layer.shadowRadius = 8; pill.layer.shadowOffset = CGSizeMake(0, 3);
            [pill setTitle:@"密码登录" forState:UIControlStateNormal];
            [pill setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            pill.titleLabel.font = [UIFont boldSystemFontOfSize:16];
            [pill setBackgroundImage:[self imageFromColor:ORANGE] forState:UIControlStateNormal];
            [pill setBackgroundImage:[self imageFromColor:[UIColor colorWithRed:0.8 green:0.38 blue:0 alpha:1]] forState:UIControlStateHighlighted];
            [pill addTarget:self action:@selector(onPillTap) forControlEvents:UIControlEventTouchUpInside];
            UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(onPillLong:)];
            lp.minimumPressDuration = 0.7;
            [pill addGestureRecognizer:lp];
            [w.rootViewController.view addSubview:pill];
            self.pill = pill;

            UILayoutGuide *g = w.rootViewController.view.layoutMarginsGuide;
            [NSLayoutConstraint activateConstraints:@[
                [pill.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
                [pill.centerYAnchor constraintEqualToAnchor:g.centerYAnchor],
                [pill.widthAnchor constraintEqualToConstant:160],
                [pill.heightAnchor constraintEqualToConstant:44],
            ]];

            LG(@"胶囊按钮已就位 build=%@", BUILD_TAG);
            [self startVisibilityMonitor];
        } @catch (NSException *e) {
            LG(@"!!! 胶囊安装失败: %@", e.reason);
        }
    });
}

- (UIImage *)imageFromColor:(UIColor *)c {
    UIGraphicsImageRenderer *r = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(1, 1)];
    return [r imageWithActions:^(UIGraphicsImageRendererContext * _Nonnull ctx) {
        [c setFill]; [ctx fillRect:CGRectMake(0, 0, 1, 1)];
    }];
}

- (void)startVisibilityMonitor {
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(tickVisibility) object:nil];
    [self performSelector:@selector(tickVisibility) withObject:nil afterDelay:1.2];
}

- (void)tickVisibility {
    @try {
        BOOL loginVisible = ([self findLoginVC] != nil);
        if (loginVisible && self.pillWindow.hidden) {
            self.pillWindow.hidden = NO;
            self.pillWindow.alpha = 0;
            [UIView animateWithDuration:0.25 animations:^{ self.pillWindow.alpha = 1; }];
        } else if (!loginVisible && !self.pillWindow.hidden) {
            [UIView animateWithDuration:0.2 animations:^{ self.pillWindow.alpha = 0; }
                             completion:^(BOOL f){ self.pillWindow.hidden = YES; }];
        }
    } @catch (NSException *e) { }
    [self performSelector:@selector(tickVisibility) withObject:nil afterDelay:1.2];
}

- (void)onPillTap {
    @try {
        if (!self.loginWindow) {
            UIWindowScene *scene = [self activeScene];
            UIWindow *w = scene ? [[UIWindow alloc] initWithWindowScene:scene]
                                : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
            w.windowLevel = UIWindowLevelAlert + 2000;   // 高于胶囊窗口，盖在最上层
            w.backgroundColor = [UIColor clearColor];
            LvccLoginVC *lc = [[LvccLoginVC alloc] init];
            lc.panel = self;
            w.rootViewController = lc;
            self.loginWindow = w;
        }
        self.loginWindow.hidden = NO;
        self.loginWindow.alpha = 0;
        [UIView animateWithDuration:0.25 animations:^{ self.loginWindow.alpha = 1; }];
    } @catch (NSException *e) {
        LG(@"!!! 弹登录卡异常: %@", e.reason);
    }
}

// 关闭登录卡（点 × 或点暗色背景都走这里）
- (void)dismissLogin {
    @try {
        if (!self.loginWindow) return;
        [UIView animateWithDuration:0.2 animations:^{ self.loginWindow.alpha = 0; }
                         completion:^(BOOL f){ self.loginWindow.hidden = YES; }];
    } @catch (NSException *e) { }
}

- (void)onPillLong:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    [self showDebugMenu];
}

- (void)copyLastText {
    @try {
        if (self.lastText.length) {
            UIPasteboard.generalPasteboard.string = self.lastText;
            LG(@"已复制 %lu 字符到剪贴板", (unsigned long)self.lastText.length);
        }
    } @catch (NSException *e) { }
}

- (UIWindow *)ensureDebugWindow {
    @try {
        if (self.debugWindow) return self.debugWindow;
        UIWindowScene *scene = [self activeScene];
        UIWindow *w = scene ? [[UIWindow alloc] initWithWindowScene:scene]
                            : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        w.windowLevel = UIWindowLevelAlert + 3000;   // 高于登录卡窗口(+2000)，自带不透明遮罩盖住登录页 → 不再有原生元素透出造成的「错乱」
        w.backgroundColor = [UIColor clearColor];
        w.rootViewController = [[UIViewController alloc] init];
        w.rootViewController.view.backgroundColor = [UIColor clearColor];
        w.hidden = YES;
        self.debugWindow = w;
        return w;
    } @catch (NSException *e) { return nil; }
}

- (void)closeDebug {
    @try {
        if (!self.debugWindow) return;
        [UIView animateWithDuration:0.2 animations:^{ self.debugWindow.alpha = 0; }
                         completion:^(BOOL f){ self.debugWindow.hidden = YES; self.debugWindow.alpha = 1; }];
    } @catch (NSException *e) { }
}

// 长按胶囊 → 自定义全屏调试菜单（不再用系统 ActionSheet，半透明遮罩会把登录页底部图标/协议文字透出来显得乱）
- (void)showDebugMenu {
    @try {
        UIWindow *w = [self ensureDebugWindow];
        if (!w) return;

        UIViewController *host = [[UIViewController alloc] init];
        host.view.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.55];   // 不透明遮罩，彻底盖住登录页
        host.modalPresentationStyle = UIModalPresentationFullScreen;

        UITapGestureRecognizer *bg = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onDebugBgTap:)];
        [host.view addGestureRecognizer:bg];

        CGFloat cardW = MIN(w.bounds.size.width - 32, 320);
        UIView *card = [[UIView alloc] init];
        card.translatesAutoresizingMaskIntoConstraints = NO;
        card.backgroundColor = [UIColor systemBackgroundColor];
        card.layer.cornerRadius = 16;
        card.userInteractionEnabled = YES;
        [host.view addSubview:card];
        self.debugCardView = card;

        UILabel *title = [[UILabel alloc] init];
        title.translatesAutoresizingMaskIntoConstraints = NO;
        title.text = @"调试菜单";
        title.font = [UIFont boldSystemFontOfSize:18];
        title.textAlignment = NSTextAlignmentCenter;
        [card addSubview:title];

        UILabel *ver = [[UILabel alloc] init];
        ver.translatesAutoresizingMaskIntoConstraints = NO;
        ver.text = BUILD_TAG;
        ver.font = [UIFont systemFontOfSize:11];
        ver.textColor = [UIColor secondaryLabelColor];
        ver.textAlignment = NSTextAlignmentCenter;
        [card addSubview:ver];

        NSArray *items = @[
            @[ @"导出存储（定位凭证键）", (id)^(void){ [self dumpStorage]; } ],
            @[ @"导出 usermodel 文件", (id)^(void){
                NSString *s = ReadUserModelFiles();
                LG(@"==== usermodel 文件 ====%@", s);
                [self showText:s title:@"usermodel 文件内容"];
            } ],
            @[ @"查看日志", (id)^(void){ [self showText:ReadLogTail(200 * 1024) title:@"日志（末尾 200KB）"]; } ],
        ];
        NSMutableArray *btns = [NSMutableArray array];
        for (NSArray *it in items) {
            NSString *t = it[0];
            void (^act)(void) = (void(^)(void))it[1];
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            b.translatesAutoresizingMaskIntoConstraints = NO;
            [b setTitle:t forState:UIControlStateNormal];
            b.titleLabel.font = [UIFont systemFontOfSize:16];
            b.backgroundColor = [UIColor secondarySystemBackgroundColor];
            b.layer.cornerRadius = 10;
            [b addTarget:self action:@selector(debugActionWrapper:) forControlEvents:UIControlEventTouchUpInside];
            objc_setAssociatedObject(b, "lvcc_debug_act", act, OBJC_ASSOCIATION_COPY);
            [card addSubview:b];
            [btns addObject:b];
        }

        UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
        close.translatesAutoresizingMaskIntoConstraints = NO;
        [close setTitle:@"关 闭" forState:UIControlStateNormal];
        close.titleLabel.font = [UIFont boldSystemFontOfSize:16];
        close.backgroundColor = ORANGE;
        [close setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        close.layer.cornerRadius = 10;
        [close addTarget:self action:@selector(closeDebug) forControlEvents:UIControlEventTouchUpInside];
        [card addSubview:close];
        [btns addObject:close];

        UILayoutGuide *g = card.layoutMarginsGuide;
        NSMutableArray *cons = [NSMutableArray arrayWithArray:@[
            [card.centerXAnchor constraintEqualToAnchor:host.view.centerXAnchor],
            [card.centerYAnchor constraintEqualToAnchor:host.view.centerYAnchor],
            [card.widthAnchor constraintEqualToConstant:cardW],
            [title.topAnchor constraintEqualToAnchor:card.topAnchor constant:16],
            [title.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
            [title.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],
            [ver.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:4],
            [ver.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
            [ver.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],
        ]];
        UIView *prev = ver;
        for (UIButton *b in btns) {
            [cons addObject:[b.topAnchor constraintEqualToAnchor:prev.bottomAnchor constant:10]];
            [cons addObject:[b.leadingAnchor constraintEqualToAnchor:g.leadingAnchor]];
            [cons addObject:[b.trailingAnchor constraintEqualToAnchor:g.trailingAnchor]];
            [cons addObject:[b.heightAnchor constraintEqualToConstant:46]];
            prev = b;
        }
        [cons addObject:[prev.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-14]];
        [NSLayoutConstraint activateConstraints:cons];

        w.rootViewController = host;
        w.hidden = NO;
        w.alpha = 0;
        [UIView animateWithDuration:0.22 animations:^{ w.alpha = 1; }];
    } @catch (NSException *e) {
        LG(@"!!! showDebugMenu 异常: %@", e.reason);
    }
}

- (void)debugActionWrapper:(UIButton *)b {
    void (^act)(void) = objc_getAssociatedObject(b, "lvcc_debug_act");
    if (act) act();
}

- (void)onDebugBgTap:(UITapGestureRecognizer *)g {
    @try {
        if (self.debugCardView && CGRectContainsPoint(self.debugCardView.frame, [g locationInView:self.debugCardView.superview])) return;
        [self closeDebug];
    } @catch (NSException *e) { }
}

- (void)showText:(NSString *)text title:(NSString *)title {
    self.lastText = text;
    @try { UIPasteboard.generalPasteboard.string = text; } @catch (NSException *e) { }
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIViewController *host = [[UIViewController alloc] init];
            host.view.backgroundColor = [UIColor systemBackgroundColor];
            UILayoutGuide *g = host.view.safeAreaLayoutGuide;

            UILabel *lab = [[UILabel alloc] init];
            lab.translatesAutoresizingMaskIntoConstraints = NO;
            lab.text = title; lab.font = [UIFont boldSystemFontOfSize:17]; lab.numberOfLines = 0;
            [host.view addSubview:lab];

            UITextView *tv = [[UITextView alloc] init];
            tv.translatesAutoresizingMaskIntoConstraints = NO;
            tv.text = text; tv.editable = NO; tv.selectable = YES;
            tv.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
            tv.backgroundColor = [UIColor secondarySystemBackgroundColor];
            tv.layer.cornerRadius = 8; tv.layoutMargins = UIEdgeInsetsMake(8, 8, 8, 8);
            [host.view addSubview:tv];

            UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
            copy.translatesAutoresizingMaskIntoConstraints = NO;
            [copy setTitle:@"再次复制全部" forState:UIControlStateNormal];
            copy.titleLabel.font = [UIFont boldSystemFontOfSize:17];
            copy.backgroundColor = [UIColor secondarySystemBackgroundColor];
            copy.layer.cornerRadius = 10;
            [copy addTarget:self action:@selector(copyLastText) forControlEvents:UIControlEventTouchUpInside];
            [host.view addSubview:copy];

            UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
            close.translatesAutoresizingMaskIntoConstraints = NO;
            [close setTitle:@"关闭" forState:UIControlStateNormal];
            close.titleLabel.font = [UIFont boldSystemFontOfSize:17];
            close.backgroundColor = [UIColor secondarySystemBackgroundColor];
            close.layer.cornerRadius = 10;
            [close addTarget:self action:@selector(showDebugMenu) forControlEvents:UIControlEventTouchUpInside];
            [host.view addSubview:close];

            [NSLayoutConstraint activateConstraints:@[
                [lab.topAnchor constraintEqualToAnchor:g.topAnchor constant:16],
                [lab.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
                [lab.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
                [tv.topAnchor constraintEqualToAnchor:lab.bottomAnchor constant:12],
                [tv.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],
                [tv.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12],
                [copy.topAnchor constraintEqualToAnchor:tv.bottomAnchor constant:12],
                [copy.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
                [copy.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
                [copy.heightAnchor constraintEqualToConstant:46],
                [close.topAnchor constraintEqualToAnchor:copy.bottomAnchor constant:10],
                [close.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
                [close.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
                [close.heightAnchor constraintEqualToConstant:46],
                [close.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-12],
            ]];
            UIWindow *w = [self ensureDebugWindow];
            if (!w) return;
            w.rootViewController = host;
            w.hidden = NO; w.alpha = 1;
        } @catch (NSException *e) {
            LG(@"!!! 展示文本失败: %@", e.reason);
        }
    });
}

- (void)closeTop {
    @try {
        UIViewController *vc = [self topVC];
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc dismissViewControllerAnimated:YES completion:nil];
    } @catch (NSException *e) { }
}

- (void)dumpStorage {
    NSMutableString *out = [NSMutableString string];
    @try {
        NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        [out appendFormat:@"===== NSUserDefaults（%lu 键）=====\n", (unsigned long)all.count];
        NSArray *keys = [all.allKeys sortedArrayUsingSelector:@selector(compare:)];
        for (NSString *k in keys) {
            id v = all[k];
            NSString *vs = [v description];
            if (vs.length > 600) vs = [[vs substringToIndex:600] stringByAppendingString:@"…(截断)"];
            [out appendFormat:@"%@ = %@%@\n", k, vs, ClassifyValue(v)];
        }
    } @catch (NSException *e) {
        [out appendFormat:@"NSUserDefaults 读取异常: %@\n", e.reason];
    }

    [out appendString:@"\n===== Keychain =====\n"];
    @try {
        NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword];
        for (id cls in classes) {
            NSDictionary *q = @{
                (__bridge id)kSecClass: cls,
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecReturnData: @YES,
                (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
            };
            CFTypeRef ref = NULL;
            if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref) == errSecSuccess && ref) {
                NSArray *items = (__bridge_transfer NSArray *)ref;
                for (NSDictionary *it in items) {
                    NSData *dat = it[(__bridge id)kSecValueData];
                    NSString *val = dat ? [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] : nil;
                    if (!val) val = [NSString stringWithFormat:@"<binary %lu bytes>", (unsigned long)dat.length];
                    if (val.length > 600) val = [[val substringToIndex:600] stringByAppendingString:@"…(截断)"];
                    [out appendFormat:@"svc=%@ acct=%@%@\n    val=%@\n",
                        it[(__bridge id)kSecAttrService] ?: @"-",
                        it[(__bridge id)kSecAttrAccount] ?: @"-",
                        ClassifyValue(dat ? [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] : nil), val];
                }
            }
        }
    } @catch (NSException *e) {
        [out appendFormat:@"Keychain 读取异常: %@\n", e.reason];
    }

    [out appendString:@"\n===== 已学习的凭证键 =====\n"];
    [out appendFormat:@"NSUserDefaults: %@\n", [gNdKeys allObjects]];
    [out appendFormat:@"Keychain: %@\n", gKcItems];

    [out appendString:@"\n===== usermodel 文件 =====\n"];
    [out appendString:ReadUserModelFiles()];

    LG(@"==== dump 开始 ====");
    LG(@"%@", out.length > 8000 ? [out substringToIndex:8000] : out);
    LG(@"==== dump 结束 ====");

    UIPasteboard.generalPasteboard.string = out;
    [self showText:out title:@"已导出并复制到剪贴板"];
}

@end

// ---------------- 启动 ----------------

__attribute__((constructor))
static void lvcc_init(void) {
    @autoreleasepool {
        @try {
            LG(@"==== LvccLogin 载入 build=%@ pid=%d ====", BUILD_TAG, getpid());
            LG(@"bundle=%@", [[NSBundle mainBundle] bundleIdentifier]);
            LG(@"home=%@", NSHomeDirectory());

            LoadKeys();
            InstallSetHook();

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                @try { [[LvccPanel shared] installPill]; }
                @catch (NSException *e) { LG(@"!!! installPill 异常: %@", e.reason); }
            });
        } @catch (NSException *e) {
            NSLog(@"[LVCC] ctor 异常: %@", e.reason);
        }
    }
}
