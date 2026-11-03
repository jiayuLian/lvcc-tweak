// LvccLogin v0.3.0 —— 零依赖版本
// 目标：iOS 15.4.1 / arm64 / TrollStore + TrollFools
//
// 为什么重写：v0.2.0 用 theos 的 tweak.mk + logos(%hook/%hookf)，
// 产物链接了 /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate，
// 并留下 _MSHookFunction / _MSHookMessageEx 两个未定义符号。
// TrollStore 设备没装 ElleKit/Substrate，dyld 在加载阶段就失败 -> App 闪退。
//
// 本版：library.mk 编译，不用任何 MSHook*，不用 logos。
// 启动走 __attribute__((constructor))，UI 走纯 UIKit，全流程 @try 兜底。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <unistd.h>

#define BUILD_TAG  @"v0.3.0-arm64-nodep"
#define LOG_PATH   @"/var/mobile/Library/Caches/lvcc_tweak.log"
#define API_HOST   @"appapi.lvcchong.com"
#define UA_STR     @"Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"

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
    } @catch (NSException *e) {
        // 写文件失败不能影响主流程
    }
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

// 判断这串东西像不像长效凭证：不是 30 秒短票、长度够、含点号或长 base64
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
           raw.length > 2000 ? [raw substringToIndex:2000] : raw);
        cb(j);
    }];
    [t resume];
}

// ---------------- 面板 ----------------

@interface LvccPanel : NSObject
@property (nonatomic, strong) UIWindow *ballWindow;
@property (nonatomic, weak) UIViewController *hostVC;
@property (nonatomic, copy) NSString *lastText;
+ (instancetype)shared;
- (void)installBall;
- (void)copyLastText;
@end

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

- (UIViewController *)topVC {
    @try {
        UIWindow *key = nil;
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w.isKeyWindow && w != self.ballWindow) { key = w; break; }
        }
        UIViewController *vc = key.rootViewController ?: self.ballWindow.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        return vc;
    } @catch (NSException *e) {
        return nil;
    }
}

- (void)installBall {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (self.ballWindow) { self.ballWindow.hidden = NO; return; }

            UIWindowScene *scene = [self activeScene];
            UIWindow *w = scene ? [[UIWindow alloc] initWithWindowScene:scene]
                                : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
            w.frame = CGRectMake(10, 150, 48, 48);
            w.windowLevel = UIWindowLevelAlert + 500;
            w.backgroundColor = [UIColor clearColor];
            w.rootViewController = [[UIViewController alloc] init];
            w.rootViewController.view.backgroundColor = [UIColor clearColor];
            w.hidden = NO;

            UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
            b.frame = CGRectMake(0, 0, 48, 48);
            b.backgroundColor = [UIColor colorWithRed:0.16 green:0.78 blue:0.42 alpha:0.92];
            b.layer.cornerRadius = 24;
            b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
            [b setTitle:@"登" forState:UIControlStateNormal];
            [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            [b addTarget:self action:@selector(onBallTap) forControlEvents:UIControlEventTouchUpInside];
            [b addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)]];
            [w.rootViewController.view addSubview:b];

            self.ballWindow = w;
            LG(@"悬浮球已就位 build=%@", BUILD_TAG);
        } @catch (NSException *e) {
            LG(@"!!! 悬浮球安装失败: %@", e.reason);
        }
    });
}

- (void)onPan:(UIPanGestureRecognizer *)g {
    @try {
        CGPoint p = [g translationInView:g.view.superview];
        CGRect f = self.ballWindow.frame;
        f.origin.x += p.x;
        f.origin.y += p.y;
        self.ballWindow.frame = f;
        [g setTranslation:CGPointZero inView:g.view.superview];
    } @catch (NSException *e) { }
}

- (void)onBallTap {
    @try {
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"驴充充 工具"
                                                                   message:BUILD_TAG
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
        [ac addAction:[UIAlertAction actionWithTitle:@"导出存储（NSUserDefaults + Keychain）"
                                               style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *a) { [self dumpStorage]; }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"手机号 + 密码登录"
                                               style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *a) { [self showLogin]; }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"查看日志" style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *a) {
            [self showText:ReadLogTail(200 * 1024) title:@"日志（末尾 200KB）"];
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];

        UIViewController *vc = [self topVC];
        if (!vc) { LG(@"!!! 找不到 topVC，面板无法弹出"); return; }
        if (ac.popoverPresentationController) {
            ac.popoverPresentationController.sourceView = vc.view;
            ac.popoverPresentationController.sourceRect =
                CGRectMake(vc.view.bounds.size.width / 2, 200, 1, 1);
        }
        [vc presentViewController:ac animated:YES completion:nil];
    } @catch (NSException *e) {
        LG(@"!!! 面板异常: %@", e.reason);
    }
}

- (void)copyLastText {
    @try {
        if (self.lastText.length) {
            UIPasteboard.generalPasteboard.string = self.lastText;
            LG(@"已复制 %lu 字符到剪贴板", (unsigned long)self.lastText.length);
        }
    } @catch (NSException *e) {
        LG(@"!!! 复制失败: %@", e.reason);
    }
}

// 通用文本展示：可滚动、可全选复制
- (void)showText:(NSString *)text title:(NSString *)title {
    self.lastText = text;
    @try { UIPasteboard.generalPasteboard.string = text; } @catch (NSException *e) { }

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIViewController *host = [[UIViewController alloc] init];
            host.view.frame = UIScreen.mainScreen.bounds;
            host.view.backgroundColor = [UIColor systemBackgroundColor];
            CGRect b = UIScreen.mainScreen.bounds;

            UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(16, 50, b.size.width - 32, 26)];
            lab.text = title;
            lab.font = [UIFont boldSystemFontOfSize:17];
            lab.numberOfLines = 1;
            [host.view addSubview:lab];

            UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(
                12, 84, b.size.width - 24, b.size.height - 84 - 130)];
            tv.text = text;
            tv.editable = NO;
            tv.selectable = YES;
            tv.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
            tv.backgroundColor = [UIColor secondarySystemBackgroundColor];
            tv.layer.cornerRadius = 8;
            [host.view addSubview:tv];

            UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
            copy.frame = CGRectMake(16, b.size.height - 118, b.size.width - 32, 46);
            [copy setTitle:@"再次复制全部" forState:UIControlStateNormal];
            copy.titleLabel.font = [UIFont boldSystemFontOfSize:17];
            copy.backgroundColor = [UIColor secondarySystemBackgroundColor];
            copy.layer.cornerRadius = 10;
            [copy addTarget:self action:@selector(copyLastText) forControlEvents:UIControlEventTouchUpInside];
            [host.view addSubview:copy];

            UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
            close.frame = CGRectMake(16, b.size.height - 62, b.size.width - 32, 46);
            [close setTitle:@"关闭" forState:UIControlStateNormal];
            close.titleLabel.font = [UIFont boldSystemFontOfSize:17];
            close.backgroundColor = [UIColor secondarySystemBackgroundColor];
            close.layer.cornerRadius = 10;
            [close addTarget:self action:@selector(closeTop) forControlEvents:UIControlEventTouchUpInside];
            [host.view addSubview:close];

            host.modalPresentationStyle = UIModalPresentationFullScreen;
            [[self topVC] presentViewController:host animated:YES completion:nil];
        } @catch (NSException *e) {
            LG(@"!!! 展示文本失败: %@", e.reason);
        }
    });
}

- (void)closeTop {
    @try {
        [[self topVC] dismissViewControllerAnimated:YES completion:nil];
    } @catch (NSException *e) { }
}

- (void)showLogin {
    @try {
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"密码登录"
                                                                   message:@"密码 8-20 位，含字母数字"
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.placeholder = @"手机号";
            tf.keyboardType = UIKeyboardTypeNumberPad;
            tf.clearButtonMode = UITextFieldViewModeWhileEditing;
        }];
        [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.placeholder = @"密码";
            tf.secureTextEntry = YES;
            tf.clearButtonMode = UITextFieldViewModeWhileEditing;
        }];
        [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

        __weak typeof(self) ws = self;
        [ac addAction:[UIAlertAction actionWithTitle:@"登录" style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *a) {
            NSString *phone = ac.textFields.firstObject.text ?: @"";
            NSString *pwd = ac.textFields.lastObject.text ?: @"";
            [ws doLoginPhone:phone password:pwd];
        }]];
        [[self topVC] presentViewController:ac animated:YES completion:nil];
    } @catch (NSException *e) {
        LG(@"!!! 登录框异常: %@", e.reason);
    }
}

- (void)doLoginPhone:(NSString *)phone password:(NSString *)pwd {
    if (phone.length != 11) {
        LG(@"手机号长度不对: %@", phone);
        [self showText:[NSString stringWithFormat:@"手机号不对：%@", phone] title:@"参数错误"];
        return;
    }
    NSDictionary *form = @{
        @"mobile": phone,
        @"validateType": @"2",
        @"password": pwd,
        @"entryType": @"5",
        @"registerOrBind": @"1",
        @"ownerId": @"0",
        @"willingnessToChargeInsurance": @"0",
        @"vsersion": @"1"
    };
    LG(@"开始密码登录 %@", phone);
    __weak typeof(self) ws = self;
    PostForm(@"/registerOrLoginUser", form, nil, ^(NSDictionary *j) {
        if (!j) { return; }
        if ([j[@"code"] integerValue] != 200) {
            NSString *m = j[@"message"] ?: j[@"msg"] ?: @"未知错误";
            LG(@"密码登录失败: code=%@ msg=%@", j[@"code"], m);
            [ws showText:[NSString stringWithFormat:@"登录失败\ncode=%@\nmessage=%@", j[@"code"], m]
                   title:@"登录失败"];
            return;
        }
        NSDictionary *d = j[@"data"] ?: @{};
        NSString *tok = d[@"userToken"];
        NSDictionary *body = JWTBody(tok);
        NSString *sum = [NSString stringWithFormat:
            @"登录成功\nsub     = %@\nuserId  = %@\n有效期  = %.0f 秒\n\n%s\n\nuserToken:\n%@\n\nrefreshToken:\n%@",
            body[@"sub"] ?: @"?", d[@"userId"] ?: @"?",
            [body[@"exp"] doubleValue] - [body[@"iat"] doubleValue],
            "注意：这条 token 只有 30 秒，写进 App 也留不住。真正要的是长效凭证。",
            tok ?: @"", d[@"refreshToken"] ?: @""];
        LG(@"密码登录成功 sub=%@ userId=%@", body[@"sub"], d[@"userId"]);
        [ws showText:sum title:@"登录结果"];
    });
}

// 导出 NSUserDefaults 全量 + Keychain 全量，结果直接显示并可复制
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
            OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
            if (st != errSecSuccess || !ref) {
                [out appendFormat:@"[class %@] status=%d\n", cls, (int)st];
                continue;
            }
            NSArray *items = (__bridge_transfer NSArray *)ref;
            for (NSDictionary *it in items) {
                NSString *svc = it[(__bridge id)kSecAttrService] ?: @"-";
                NSString *acct = it[(__bridge id)kSecAttrAccount] ?: @"-";
                NSData *dat = it[(__bridge id)kSecValueData];
                NSString *val = dat ? [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] : nil;
                if (!val) val = dat ? [NSString stringWithFormat:@"<binary %lu bytes>", (unsigned long)dat.length] : @"<nil>";
                if (val.length > 600) val = [[val substringToIndex:600] stringByAppendingString:@"…(截断)"];
                [out appendFormat:@"svc=%@ acct=%@%@\n    val=%@\n", svc, acct,
                    ClassifyValue(dat ? [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] : nil),
                    val];
            }
        }
    } @catch (NSException *e) {
        [out appendFormat:@"Keychain 读取异常: %@\n", e.reason];
    }

    [out appendString:@"\n===== 文件系统里的可疑文件 =====\n"];
    @try {
        NSString *home = NSHomeDirectory();
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *dirs = @[
            [home stringByAppendingPathComponent:@"Library/Preferences"],
            [home stringByAppendingPathComponent:@"Documents"],
            [home stringByAppendingPathComponent:@"Library/Application Support"],
            [home stringByAppendingPathComponent:@"Library/Caches"]
        ];
        for (NSString *d in dirs) {
            NSArray *fs = [fm contentsOfDirectoryAtPath:d error:nil];
            if (fs.count) [out appendFormat:@"%@:\n  %@\n", d, [fs componentsJoinedByString:@", "]];
        }
    } @catch (NSException *e) { }

    LG(@"==== dump 开始 ====");
    LG(@"%@", out.length > 8000 ? [out substringToIndex:8000] : out);
    LG(@"==== dump 结束（完整内容见弹窗）====");

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

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                @try {
                    [[LvccPanel shared] installBall];
                } @catch (NSException *e) {
                    LG(@"!!! installBall 异常: %@", e.reason);
                }
            });
        } @catch (NSException *e) {
            NSLog(@"[LVCC] ctor 异常: %@", e.reason);
        }
    }
}
