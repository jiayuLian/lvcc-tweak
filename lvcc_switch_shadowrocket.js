/*
 * 驴充充小程序 · 纯手机换号（Shadowrocket 版 v2）
 *
 * 只改 URL，不改 body / headers / method。
 * 把 /getUnionInfo 换成带完整参数的 /registerOrLoginUser。
 *
 * v2 新增：支持 ?mobile=off 清除号码（v1 只认 1 开头的 11 位，输 off 会被忽略）
 *
 * 换号流程：
 *   1) 微信里点收藏的 https://h5.lvcchong.com/__lvcc_switch__?mobile=目标手机号
 *   2) 重开小程序（建议先删掉再进），点任意页面
 *   恢复：把上面的手机号换成 off
 *
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

  // 切换端点：记号码 / 清除，原样放行（服务器返回 404 不影响）
  if (/lvcchong/i.test(url) && url.indexOf('/__lvcc_switch__') >= 0) {
    var m = url.match(/[?&]mobile=([^&#]*)/);
    var num = '';
    if (m) {
      try { num = decodeURIComponent(m[1]); } catch (e) { num = m[1]; }
    }
    if (/^1\d{10}$/.test(num)) {
      kvSet(KEY_MOBILE, num);
      notify('驴充充换号', '已切换到 ' + num, '重开小程序，点一下页面即生效');
    } else if (num === 'off' || num === '0') {
      kvSet(KEY_MOBILE, '');
      notify('驴充充换号', '已清除', '下次小程序登录恢复为微信原始账号');
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
    $done({});                       // 没设号 = 保持小程序原来的微信登录
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
