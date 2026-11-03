// LvccLogin —— 驴充充 iOS 密码登录注入模块
// 目标：iOS 15.4.1 / arm64 / TrollStore 环境
// 作用：给 App 挂一个悬浮按钮，点开输入手机号+密码，直接调 registerOrLoginUser 拿 token，
//      同时把 App 自己的存储写入全部记进日志（用于定位 token 落盘 key）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#define BUILD_TAG  @"v0.2.0-arm64"
#define LOG_PATH   @"/var/mobile/Library/Caches/lvcc_tweak.log"
#define API_HOST   @"appapi.lvcchong.com"
#define UA_STR     @"Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"

static void LG(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], msg];
    NSLog(@"[LVCC] %@", msg);
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

static NSString *UEnc(NSString *s) {
    if (!s) return @"";
    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
                          @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"];
    return [s stringByAddingPercentEncodingWithAllowedCharacters:ok] ?: s;
}

static NSDictionary *JWTBody(NSString *tok) {
    NSArray *parts = [tok componentsSeparatedByString:@"."];
    if (parts.count != 3) return nil;
    NSString *p = parts[1];
    p = [p stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    p = [p stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    while (p.length % 4) p = [p stringByAppendingString:@"="];
    NSData *d = [[NSData alloc] initWithBase64EncodedString:p options:0];
    if (!d) return nil;
    return [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
}

// ---------- HTTP ----------

static void PostForm(NSString *path, NSDictionary *form, NSString *token, void (^cb)(NSDictionary *)) {
    NSMutableArray *pairs = [NSMutableArray array];
    for (NSString *k in form.allKeys) {
        [pairs addObject:[NSString stringWithFormat:@"%@=%@", UEnc(k), UEnc([form[k] description])]];
    }
    NSString *bodyStr = [pairs componentsJoinedByString:@"&"];

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"https://%@%@", API_HOST, path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"https://h5.lvcchong.com/" forHTTPHeaderField:@"Referer"];
    [req setValue:@"https://h5.lvcchong.com" forHTTPHeaderField:@"Origin"];
    [req setValue:UA_STR forHTTPHeaderField:@"User-Agent"];
    [req setValue:(token ?: @"") forHTTPHeaderField:@"token"];
    req.HTTPBody = [bodyStr dataUsingEncoding:NSUTF8StringEncoding];

    LG(@">>> POST %@  body=%@", path, bodyStr.length > 800 ? [bodyStr substringToIndex:800] : bodyStr);

    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err) { LG(@"!!! %@ 网络错误: %@", path, err.localizedDescription); cb(nil); return; }
        NSDictionary *j = nil;
        @try { j = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil]; } @catch (NSException *e) { }
        NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        LG(@"<<< %@  status=%ld  body=%@", path, (long)((NSHTTPURLResponse *)resp).statusCode,
           raw.length > 1500 ? [raw substringToIndex:1500] : raw);
        cb(j);
    }];
    [t resume];
}

// ---------- 面板 ----------

@interface LvccPanel : NSObject
@property (nonatomic, strong) UIWindow *ballWindow;
+ (instancetype)shared;
- (void)installBall;
- (void)onBallTap;
- (void)dumpDefaults;
- (void)dumpKeychain;
@end

@implementation LvccPanel

+ (instancetype)shared {
    static LvccPanel *o; static dispatch_once_t once;
    dispatch_once(&once, ^{ o = [[LvccPanel alloc] init]; });
    return o;
}

- (UIWindowScene *)activeScene {
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]] &&
            (s.activationState == UISceneActivationStateForegroundActive ||
             s.activationState == UISceneActivationStateForegroundInactive)) {
            return (UIWindowScene *)s;
        }
    }
    return nil;
}

- (UIViewController *)topVC {
    UIWindow *key = nil;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w.isKeyWindow && w != self.ballWindow) { key = w; break; }
    }
    UIViewController *vc = key.rootViewController ?: self.ballWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

- (void)installBall {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.ballWindow) { self.ballWindow.hidden = NO; return; }
        UIWindowScene *scene = [self activeScene];
        UIWindow *w = scene ? [[UIWindow alloc] initWithWindowScene:scene]
                            : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        w.frame = CGRectMake(10, 150, 48, 48);
        w.windowLevel = UIWindowLevelAlert + 500;
        w.backgroundColor = [UIColor clearColor];
        w.rootViewController = [[UIViewController alloc] init];
        w.rootViewController.view.backgroundColor = [UIColor clearColor];

        UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
        b.frame = CGRectMake(0, 0, 48, 48);
        b.backgroundColor = [UIColor colorWithRed:0.16 green:0.78 blue:0.42 alpha:0.92];
        b.layer.cornerRadius = 24;
        b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
        [b setTitle:@"登" forState:UIControlStateNormal];
        [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [b addTarget:self action:@selector(onBallTap) forControlEvents:UIControlEventTouchUpInside];
        // 拖动
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPan:)];
        [b addGestureRecognizer:pan];
        [w.rootViewController.view addSubview:b];
        w.hidden = NO;
        self.ballWindow = w;
        LG(@"悬浮球已就位");
    });
}

- (void)onPan:(UIPanGestureRecognizer *)g {
    UIView *v = g.view;
    CGPoint p = [g translationInView:v.superview];
    CGRect f = self.ballWindow.frame;
    f.origin.x += p.x; f.origin.y += p.y;
    self.ballWindow.frame = f;
    [g setTranslation:CGPointZero inView:v.superview];
}

- (void)onBallTap {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"驴充充 密码登录"
                                                               message:@"手机号 + 密码直接换 token"
                                                        preferredStyle:UIAlertControllerStyleActionSheet];
    [ac addAction:[UIAlertAction actionWithTitle:@"手机号+密码登录" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) { [self showLogin]; }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"导出 NSUserDefaults 全部键值" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) { [self dumpDefaults]; }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"导出 Keychain 条目" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) { [self dumpKeychain]; }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    UIViewController *vc = [self topVC];
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad && ac.popoverPresentationController) {
        ac.popoverPresentationController.sourceView = vc.view;
        ac.popoverPresentationController.sourceRect = CGRectMake(vc.view.bounds.size.width / 2, 200, 1, 1);
    }
    [vc presentViewController:ac animated:YES completion:nil];
}

- (void)showLogin {
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
}

- (void)doLoginPhone:(NSString *)phone password:(NSString *)pwd {
    if (phone.length != 11) { LG(@"手机号长度不对: %@", phone); return; }
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
    PostForm(@"/registerOrLoginUser", form, nil, ^(NSDictionary *j) {
        if (!j) return;
        if ([j[@"code"] integerValue] != 200) {
            LG(@"密码登录失败: code=%@ msg=%@", j[@"code"], j[@"message"] ?: j[@"msg"]);
            dispatch_async(dispatch_get_main_queue(), ^{
                [self toast:[NSString stringWithFormat:@"登录失败：%@", j[@"message"] ?: j[@"msg"] ?: @"未知"]];
            });
            return;
        }
        NSDictionary *d = j[@"data"];
        NSString *tok = d[@"userToken"];
        NSDictionary *body = JWTBody(tok);
        LG(@"密码登录成功 sub=%@ userId=%@ jti=%@ 有效期=%.0fs",
           body[@"sub"], d[@"userId"], body[@"jti"],
           [body[@"exp"] doubleValue] - [body[@"iat"] doubleValue]);
        LG(@"userToken=%@", tok);
        LG(@"refreshToken=%@", d[@"refreshToken"]);
        dispatch_async(dispatch_get_main_queue(), ^{
            [self toast:[NSString stringWithFormat:@"已拿到 token (sub=%@)，详见日志", body[@"sub"] ?: @"?"]];
        });
    });
}

- (void)toast:(NSString *)msg {
    LG(@"[toast] %@", msg);
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"结果" message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [[self topVC] presentViewController:ac animated:YES completion:nil];
}

- (void)dumpDefaults {
    NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
    LG(@"==== NSUserDefaults dump (%lu keys) ====", (unsigned long)all.count);
    NSArray *keys = [all.allKeys sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *k in keys) {
        id v = all[k];
        NSString *vs = [v description];
        if (vs.length > 400) vs = [vs substringToIndex:400];
        LG(@"  UD %@ = %@", k, vs);
    }
    LG(@"==== NSUserDefaults dump end ====");
}

- (void)dumpKeychain {
    // App 自己的 keychain 条目：kSecAttrService 不限，按 bundle 归属自动隔离
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword];
    LG(@"==== Keychain dump start ====");
    for (id cls in classes) {
        NSDictionary *q = @{
            (__bridge id)kSecClass: cls,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecReturnData: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
        };
        CFTypeRef out = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
        if (st != errSecSuccess || !out) { LG(@"  KC class=%@ status=%d", cls, (int)st); continue; }
        NSArray *items = (__bridge_transfer NSArray *)out;
        for (NSDictionary *it in items) {
            NSString *svc = it[(__bridge id)kSecAttrService];
            NSString *acct = it[(__bridge id)kSecAttrAccount];
            NSData *dat = it[(__bridge id)kSecValueData];
            NSString *val = dat ? [[NSString alloc] initWithData:dat encoding:NSUTF8StringEncoding] : nil;
            LG(@"  KC svc=%@ acct=%@ val=%@", svc, acct, val.length > 400 ? [val substringToIndex:400] : (val ?: @"<binary>"));
        }
    }
    LG(@"==== Keychain dump end ====");
}

@end

// ---------- Hooks：记录 App 自己的存储写入 ----------

%hook NSUserDefaults

- (void)setObject:(id)value forKey:(NSString *)defaultName {
    if ([defaultName isKindOfClass:[NSString class]]) {
        NSString *vs = [value description];
        LG(@"[UD.set] %@ = %@", defaultName, vs.length > 400 ? [vs substringToIndex:400] : vs);
    }
    %orig;
}

- (void)setValue:(id)value forKey:(NSString *)key {
    if ([key isKindOfClass:[NSString class]]) {
        NSString *vs = [value description];
        LG(@"[UD.setValue] %@ = %@", key, vs.length > 400 ? [vs substringToIndex:400] : vs);
    }
    %orig;
}

%end

%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    LG(@"[KC.add] %@", (__bridge NSDictionary *)attributes);
    return %orig;
}

%hookf(OSStatus, SecItemUpdate, CFDictionaryRef query, CFDictionaryRef attrs) {
    LG(@"[KC.update] q=%@ attr=%@", (__bridge NSDictionary *)query, (__bridge NSDictionary *)attrs);
    return %orig;
}

%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    OSStatus st = %orig;
    // 限流：App 会高频查 keychain，全量写日志会把文件撑爆、拖慢启动。
    // 只记前 400 次，且只记 service/account 两个关键字段。
    static int kcCopyCount = 0;
    if (__sync_fetch_and_add(&kcCopyCount, 1) < 400) {
        NSDictionary *q = (__bridge NSDictionary *)query;
        NSString *svc = q[(__bridge id)kSecAttrService];
        NSString *acct = q[(__bridge id)kSecAttrAccount];
        if (svc || acct) LG(@"[KC.copy] svc=%@ acct=%@ -> %d", svc ?: @"-", acct ?: @"-", (int)st);
    }
    return st;
}

// ---------- 启动 ----------

%ctor {
    LG(@"==== LvccLogin 载入 build=%@ pid=%d ====", BUILD_TAG, getpid());
    LG(@"bundle=%@", [[NSBundle mainBundle] bundleIdentifier]);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[LvccPanel shared] installBall];
        [[LvccPanel shared] dumpDefaults];
    });
}
