/*
 * 驴充充小程序 · 纯手机换号（Shadowrocket 版，只改 URL，不改 body）
 *
 * 与 lvcc_miniapp_switch.js 的区别：本脚本不改 body / headers / method，
 * 只在 request 阶段把 /getUnionInfo 的 URL 换成带完整参数的 /registerOrLoginUser。
 * 因此 Shadowrocket 配置里不需要 requires-body=1，兼容性最好。
 *
 * 实测依据（_wxapkg/probe_query_param.js，全部走快代理真实打接口）：
 *   POST /registerOrLoginUser?mobile=xxx&ownerId=0&entryType=5
 *        &registerOrBind=1&validateType=3&checkDataValue=
 *   + 空 body                        -> code=200，签出 userToken/refreshToken/userId
 *   + 原始 getUnionInfo form body     -> code=200（body 被忽略）
 *   + JSON body / application/json   -> code=200
 *   GET 同 URL                       -> Tomcat 405，所以必须保持原 POST 方法不动
 *   换不同手机号 -> userId 不同 / code=1017，证明 query 里的 mobile 被服务端真实读取
 *   手机号不存在 -> code=1017「请使用短信验证码进行注册！」，不会建号
 *
 * 换号流程（全在手机）：
 *   1) 微信里点收藏的 https://h5.lvcchong.com/__lvcc_switch__?mobile=目标手机号
 *      -> 本脚本记住号码并弹一条通知（页面 404 无所谓）
 *   2) 重开驴充充小程序，随便点一页（或等 30 秒）
 *      -> 短票 402 -> reshToken() 打 POST /getUnionInfo -> URL 被本脚本改掉
 *      -> 服务端按 URL 里的 mobile 签票，小程序照常覆盖三键
 *
 * 依赖：Shadowrocket / Stash / Surge 的 $persistentStore，QX 的 $prefs（两者都兼容）
 * 只用 ES5 语法，兼容 JavaScriptCore。
 */
var KEY_MOBILE = 'lvcc_phone_current_mobile';
var KEY_NOTIFY_AT = 'lvcc_login_notify_at';
var NOTIFY_GAP_MS = 600000;              // 10 分钟节流：402 刷新会反复触发，避免刷屏
var BASE = 'https://appapi.lvcchong.com';
var LOGIN_QUERY = '/registerOrLoginUser?mobile=';

// Surge / Stash / Shadowrocket 用 $persistentStore，Quantumult X 用 $prefs
function kvGet(k) {
  var v = '';
  try { if (typeof $persistentStore !== 'undefined') v = $persistentStore.read(k) || ''; } catch (e) {}
  if (!v) {
    try { if (typeof $prefs !== 'undefined') v = $prefs.valueForKey(k) || ''; } catch (e) {}
  }
  return v;
}
function kvSet(k, v) {
  try { if (typeof $persistentStore !== 'undefined') $persistentStore.write(String(v), k); } catch (e) {}
  try { if (typeof $prefs !== 'undefined') $prefs.setValueForKey(String(v), k); } catch (e) {}
}
function notify(title, sub, msg) {
  try { if (typeof $notify !== 'undefined') $notify(title, sub, msg); } catch (e) {}
}
// 命中登录接口时给一条可见回执，用来区分「脚本没跑」和「脚本跑了但没换号」
function notifyLoginHit(mobile) {
  var now = Date.now();
  var last = parseInt(kvGet(KEY_NOTIFY_AT), 10) || 0;
  if (now - last < NOTIFY_GAP_MS) return;
  kvSet(KEY_NOTIFY_AT, String(now));
  notify('驴充充换号', '登录请求已改写 → ' + mobile, '若号码未变，删小程序重开或等一次 402 刷新');
}

function handleRequest() {
  var url = $request.url || '';

  // 切换端点：只记号码，原样放行（服务器返回 404 不影响）
  if (/lvcchong/i.test(url) && url.indexOf('/__lvcc_switch__') >= 0) {
    var m = url.match(/[?&]mobile=([^&#]*)/);
    var num = '';
    if (m) {
      try { num = decodeURIComponent(m[1]); } catch (e) { num = m[1]; }
    }
    if (/^1\d{10}$/.test(num)) {
      kvSet(KEY_MOBILE, num);
      notify('驴充充换号', '已切换到 ' + num, '重开小程序，点一下页面即生效');
    }
    $done({});
    return;
  }

  // 只改这两个登录入口，其余接口一律透传
  if (!/^https:\/\/appapi\.lvcchong\.com\/(getUnionInfo|registerOrLoginUser)/i.test(url)) {
    $done({});
    return;
  }
  var mobile = kvGet(KEY_MOBILE);
  if (!/^1\d{10}$/.test(mobile)) {
    $done({});                       // 没设过号 = 保持小程序原来的微信登录
    return;
  }

  var newUrl = BASE + LOGIN_QUERY + mobile +
               '&ownerId=0&entryType=5&registerOrBind=1' +
               '&validateType=3&checkDataValue=';

  // 显式带回 body/headers：合并语义与替换语义的实现下都安全。
  // POST 方法、Content-Length 全部保持原样（body 没动，长度自然一致）。
  var out = { url: newUrl };
  if (typeof $request.body !== 'undefined') out.body = $request.body;
  if ($request.headers) out.headers = $request.headers;
  notifyLoginHit(mobile);
  $done(out);
}

// 本脚本只挂在 http-request 上；万一被挂到 response 阶段，直接放行不误改
if (typeof $response !== 'undefined') $done({});
else if (typeof $request !== 'undefined') handleRequest();
else $done({});
