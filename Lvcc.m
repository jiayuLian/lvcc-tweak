// LvccLogin v0.5.0 —— 零依赖版本（无 Substrate / 无 logos / 无 MSHook）
// 目标：iOS 15.4.1 / arm64 / TrollStore + TrollFools
//
// 行为：
//   1) 注入后自动在「登录页」底部浮出一枚橙色胶囊按钮「密码登录」。
//   2) 点按 → 弹出登录卡（手机号 + 密码 + 确定）。
//   3) 确定 → 调密码登录接口(sub=5) 拿到 userToken / refreshToken / userId，
//      原样写回 App 的 NSUserDefaults / Keychain（键名用「启动时扫描 + 运行时 hook」
//      两种方式动态学习，无需知道 App 内部字段名），随后重启 App 进入已登录态。
//   4) 长按胶囊 → 调试菜单（导出存储 / 查看日志），便于校准凭证键。
//
// 为什么不是悬浮球 + 弹窗式输入：用户要的是登录页上一个能点的按钮，
// 所以改用跟随登录页显隐的小窗胶囊，并配自定义登录卡 UI。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <unistd.h>

#define BUILD_TAG  @"v0.5.0-arm64-nodep"
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
// 目标：不需要逆 App 就能知道它把 token 存在哪个 NSUserDefaults 键 / Keychain 项里。
// 方法一：注入时扫描当前存储里已经存在的 token 值，记下它的键名（值过期没关系，键名稳定）。
// 方法二：hook NSUserDefaults setObject:forKey:，App 自己写 token 时顺手记下键名。
//        这样即便用户此前已登出（键被删），只要他之后做过一次原生验证码登录，
//        我们也能学到正确的键，下次密码登录直接写回去。

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

    // 1) 读持久化
    @try {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:KEYS_PATH];
        if (d[@"nd"]) [gNdKeys addObjectsFromArray:d[@"nd"]];
        if (d[@"kc"]) [gKcItems addObjectsFromArray:d[@"kc"]];
    } @catch (NSException *e) { }

    // 2) 扫描当前 NSUserDefaults 中已存在的 token 值 → 记键名
    @try {
        NSDictionary *all = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
        for (NSString *k in all) {
            id v = all[k];
            NSString *s = [v isKindOfClass:[NSString class]] ? v : nil;
            if (s.length && ClassifyValue(s).length) [gNdKeys addObject:k];
        }
    } @catch (NSException *e) { }

    // 3) 扫描 Keychain 中已存在的 token 值 → 记 service/account
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

// hook NSUserDefaults setObject:forKey:（直接替换 IMP，零依赖）
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

// 把登录拿到的凭证写回 App 本地存储，键名用学到的 + 一组高频默认键（双保险）
static void WriteTokens(NSDictionary *data) {
    @try {
        NSString *ut  = [data[@"userToken"]   description] ?: @"";
        NSString *rt  = [data[@"refreshToken"] description] ?: @"";
        NSString *uid = [data[@"userId"]      description] ?: @"";
        NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];

        // 高频默认键（绝大多数 App 用这几个名字）
        if (ut.length)  { [ud setObject:ut forKey:@"userToken"]; [ud setObject:ut forKey:@"token"];       [ud setObject:ut forKey:@"accessToken"]; }
        if (rt.length)  { [ud setObject:rt forKey:@"refreshToken"]; }
        if (uid.length) { [ud setObject:uid forKey:@"userId"]; [ud setObject:uid forKey:@"uid"]; }
        if (data[@"mobile"]) [ud setObject:data[@"mobile"] forKey:@"mobile"];

        // 学到的键：根据原值的形态决定写 userToken 还是 refreshToken
        for (NSString *k in gNdKeys) {
            id cur = [ud objectForKey:k];
            NSString *cs = [cur isKindOfClass:[NSString class]] ? cur : nil;
            if (cs.length >= 32) {
                if (JWTBody(cs)) {
                    if (ut.length) [ud setObject:ut forKey:k];          // 原值就是 JWT → 写新的 userToken(JWT)
                } else {
                    [ud setObject:(rt.length ? rt : ut) forKey:k];     // 原值是长串(多为 refresh) → 写 refresh
                }
            }
        }

        // 整个 data 当作用户对象写回，覆盖按对象读取的 App
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

        [ud synchronize];

        // 学到的 Keychain 项：用 userToken 更新数据
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
        LG(@"凭证已写回：ND键=%lu  KC项=%lu  userToken.len=%lu", (unsigned long)gNdKeys.count, (unsigned long)gKcItems.count, (unsigned long)ut.length);
    } @catch (NSException *e) {
        LG(@"!!! WriteTokens 异常: %@", e.reason);
    }
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

// ---------------- 登录卡 UI ----------------

@interface LvccLoginVC : UIViewController
@property (nonatomic, weak)   id panel;
@property (nonatomic, strong) UITextField *phoneF;
@property (nonatomic, strong) UITextField *pwdF;
@property (nonatomic, strong) UIButton *okBtn;
@property (nonatomic, strong) UILabel  *errLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spin;
@property (nonatomic, strong) UIView  *cardView;
@end

@implementation LvccLoginVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.45];

    // 点击暗色背景才关闭（卡片内部不触发）
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

    // 顶部渐变标题条
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

    [card addSubview:self.phoneF];
    self.cardView = card;
    [card addSubview:self.pwdF];
    [card addSubview:self.errLabel];
    [card addSubview:self.okBtn];
    [card addSubview:cancel];

    UILayoutGuide *cg = card.layoutMarginsGuide;

    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [card.widthAnchor constraintEqualToConstant:cardW],

        [header.topAnchor constraintEqualToAnchor:card.topAnchor],
        [header.leadingAnchor constraintEqualToAnchor:card.leadingAnchor],
        [header.trailingAnchor constraintEqualToAnchor:card.trailingAnchor],
        [header.heightAnchor constraintEqualToConstant:64],

        [title.topAnchor constraintEqualToAnchor:header.topAnchor constant:12],
        [title.leadingAnchor constraintEqualToAnchor:header.leadingAnchor constant:16],
        [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:3],
        [sub.leadingAnchor constraintEqualToAnchor:header.leadingAnchor constant:16],

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

    // 让渐变层跟随 header 尺寸
    dispatch_async(dispatch_get_main_queue(), ^{
        gl.frame = header.bounds;
    });
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

- (void)onDimTap:(UITapGestureRecognizer *)g {
    CGPoint p = [g locationInView:self.view];
    if (self.cardView && CGRectContainsPoint(self.cardView.frame, p)) return; // 点在卡片内不关闭
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)onCancel {
    [self dismissViewControllerAnimated:YES completion:nil];
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
            NSDictionary *d = j[@"data"] ?: @{};
            WriteTokens(d);
            [ws showSuccessThenRelaunch];
        });
    });
}

- (void)resetOK {
    self.okBtn.enabled = YES;
    [self.okBtn setTitle:@"确 定" forState:UIControlStateNormal];
}

- (void)showSuccessThenRelaunch {
    for (UIView *v in self.view.subviews) v.hidden = YES;
    self.view.backgroundColor = [UIColor systemBackgroundColor];

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
    t2.text = @"正在重启 App 进入已登录状态…";
    t2.font = [UIFont systemFontOfSize:14];
    t2.textColor = [UIColor secondaryLabelColor];
    t2.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:t2];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [check.widthAnchor constraintEqualToConstant:72], [check.heightAnchor constraintEqualToConstant:72],
        [check.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [check.centerYAnchor constraintEqualToAnchor:g.centerYAnchor constant:-30],
        [t1.topAnchor constraintEqualToAnchor:check.bottomAnchor constant:16],
        [t1.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
        [t2.topAnchor constraintEqualToAnchor:t1.bottomAnchor constant:8],
        [t2.centerXAnchor constraintEqualToAnchor:g.centerXAnchor],
    ]];

    LG(@"登录成功，1.4s 后 exit 让 App 重新读取凭证");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        exit(0);   // 干净退出，App 重新启动后读取写回的凭证 → 直接进入已登录态
    });
}

@end

// ---------------- 胶囊按钮 + 面板 ----------------

@interface LvccPanel : NSObject
@property (nonatomic, strong) UIWindow *pillWindow;
@property (nonatomic, strong) UIButton *pill;
@property (nonatomic, weak)   UIViewController *hostVC;
@property (nonatomic, copy)   NSString *lastText;
+ (instancetype)shared;
- (void)installPill;
- (void)startVisibilityMonitor;
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

- (UIWindow *)keyWindow {
    @try {
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w.isKeyWindow) return w;
        }
    } @catch (NSException *e) { }
    return UIApplication.sharedApplication.windows.firstObject;
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

// 判断某个 VC 的视图是否像「登录页」：有输入框 + 有登录/手机号/微信/Apple 按钮
- (BOOL)vcLooksLikeLogin:(UIViewController *)vc {
    if (!vc || !vc.isViewLoaded || !vc.view) return NO;
    __block BOOL hasTF = NO, hasLoginBtn = NO;
    void (^walk)(UIView *) = ^(UIView *v) {
        for (UIView *sub in v.subviews) {
            if ([sub isKindOfClass:[UITextField class]]) hasTF = YES;
            if ([sub isKindOfClass:[UIButton class]]) {
                NSString *t = [((UIButton *)sub) titleForState:UIControlStateNormal];
                if (t && ([t containsString:@"登录"] || [t containsString:@"手机号"] ||
                         [t containsString:@"微信"] || [t containsString:@"Apple"] ||
                         [t containsString:@"验证码"])) hasLoginBtn = YES;
            }
            walk(sub);
        }
    };
    walk(vc.view);
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
            if ([self vcLooksLikeLogin:vc]) return vc;
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
            // 小窗只覆盖底部胶囊区域，不挡住 App 自身按钮
            CGRect sr = UIScreen.mainScreen.bounds;
            CGFloat ww = 200, wh = 84;
            w.frame = CGRectMake((sr.size.width - ww) / 2.0,
                                 sr.size.height - wh - 30, ww, wh);
            w.windowLevel = UIWindowLevelAlert + 1000;
            w.backgroundColor = [UIColor clearColor];
            w.rootViewController = [[UIViewController alloc] init];
            w.rootViewController.view.backgroundColor = [UIColor clearColor];
            w.hidden = YES;   // 默认隐藏，登录页出现才显示
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
    // 每 1.2s 检测登录页是否存在，存在则渐显胶囊，否则隐藏
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
        LvccLoginVC *vc = [[LvccLoginVC alloc] init];
        vc.panel = self;
        vc.modalPresentationStyle = UIModalPresentationOverFullScreen;
        UIViewController *host = [self topVC];
        if (!host) { LG(@"!!! 找不到 topVC，无法弹出登录卡"); return; }
        [host presentViewController:vc animated:YES completion:nil];
    } @catch (NSException *e) {
        LG(@"!!! 弹登录卡异常: %@", e.reason);
    }
}

- (void)onPillLong:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    @try {
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"调试菜单"
                                                                   message:BUILD_TAG
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
        [ac addAction:[UIAlertAction actionWithTitle:@"导出存储（定位凭证键）"
                                               style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *a) { [self dumpStorage]; }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"查看日志" style:UIAlertActionStyleDefault
                                             handler:^(UIAlertAction *a) {
            [self showText:ReadLogTail(200 * 1024) title:@"日志（末尾 200KB）"];
        }]];
        [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
        UIViewController *vc = [self topVC];
        if (!vc) return;
        if (ac.popoverPresentationController) {
            ac.popoverPresentationController.sourceView = vc.view;
            ac.popoverPresentationController.sourceRect = CGRectMake(vc.view.bounds.size.width/2, 200, 1, 1);
        }
        [vc presentViewController:ac animated:YES completion:nil];
    } @catch (NSException *e) { }
}

- (void)copyLastText {
    @try {
        if (self.lastText.length) {
            UIPasteboard.generalPasteboard.string = self.lastText;
            LG(@"已复制 %lu 字符到剪贴板", (unsigned long)self.lastText.length);
        }
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
            [close addTarget:self action:@selector(closeTop) forControlEvents:UIControlEventTouchUpInside];
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
            host.modalPresentationStyle = UIModalPresentationFullScreen;
            UIViewController *vc = [self topVC];
            if (!vc) { LG(@"!!! showText 找不到 topVC"); return; }
            [vc presentViewController:host animated:YES completion:nil];
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

            LoadKeys();        // 先学凭证键（读已有值 + 加载持久化）
            InstallSetHook();  // 再 hook setObject，运行时持续学习

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
