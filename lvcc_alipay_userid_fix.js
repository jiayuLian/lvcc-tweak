/**
 * lvcc_alipay_userid_fix.js —— 修「支付异常：userId是空」
 *
 * 触发场景：驴充充 APP 选支付宝付款 → APP 拼
 *   alipays://platformapi/startapp?appId=2018100261563741
 *     &page=subPackageB/pages/vBillPay/vBillPay?<queryUrl>
 *     &thirdPartSchema=lvccbcpayment://
 *   拉起支付宝小程序。小程序 vBillPay 页 onLoad 读 query.userId，为空就弹这个 toast。
 *
 * queryUrl 不是 APP 本地拼的，是 /charge/pay 响应 data 里的字段下发的；
 * 而服务端生成 queryUrl 用的 userId 来自 /charge/pay 请求体的 userId。
 * 所以两头都可能丢：
 *   (1) 请求体 userId= 为空        → 本脚本在 http-request 阶段从 token 的 JWT 补；
 *   (2) 响应 queryUrl 缺/空 userId → 本脚本在 http-response 阶段补。
 *
 * alipays:// 是系统 scheme 跳转，不走 VPN，代理改不到；能改的只有 HTTPS 下单接口，
 * 让 APP 自己拿补全后的参数去拼 scheme。这是选这两个切入点的原因。
 *
 * Shadowrocket 模块里两条规则共用同一个 script-path，靠 $response 是否存在区分阶段。
 * 未命中或未改动时静默放行，不会改变原有换号规则。
 */
var TAG = 'lvcc-alipay-fix';
var KEY_UID = 'lvcc_last_userid';
var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/* 手写 base64url 解码：Shadowrocket 的 JS 核心不保证有 atob / Buffer */
function b64urlJson(seg) {
  var s = String(seg || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  s = s.replace(/[^A-Za-z0-9+/=]/g, '');
  var out = '', i = 0, e1, e2, e3, e4;
  for (; i < s.length;) {
    e1 = B64.indexOf(s.charAt(i++)); e2 = B64.indexOf(s.charAt(i++));
    e3 = B64.indexOf(s.charAt(i++)); e4 = B64.indexOf(s.charAt(i++));
    if (e1 < 0 || e2 < 0) break;
    out += String.fromCharCode((e1 << 2) | (e2 >> 4));
    if (e3 >= 0 && e3 < 64) out += String.fromCharCode(((e2 & 15) << 4) | (e3 >> 2));
    if (e4 >= 0 && e4 < 64) out += String.fromCharCode(((e3 & 3) << 6) | e4);
  }
  var txt;
  try { txt = decodeURIComponent(escape(out)); } catch (e) { txt = out; }
  try { return JSON.parse(txt); } catch (e) { return null; }
}

function headerVal(headers, names) {
  if (!headers) return '';
  for (var i = 0; i < names.length; i++) {
    for (var h in headers) {
      if (String(h).toLowerCase() === names[i].toLowerCase()) return String(headers[h] || '');
    }
  }
  return '';
}

/* APP 的登录票是 JWT：payload {"sub":"5","userId":"112489396",...} */
function uidFromToken(headers) {
  var t = headerVal(headers, ['token', 'userToken', 'accessToken', 'authToken', 'Authorization']);
  t = t.replace(/^Bearer\s+/i, '');
  var p = t.split('.');
  if (p.length < 2) return '';
  var j = b64urlJson(p[1]);
  if (!j) return '';
  return String(j.userId || j.uid || j.user_id || '');
}

function qsGet(b, k) {
  var m = new RegExp('(?:^|&)' + k + '=([^&]*)').exec(String(b || ''));
  if (!m) return null;
  try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; }
}

function qsSet(b, k, v) {
  var s = String(b || '');
  var re = new RegExp('((?:^|&)' + k + '=)[^&]*');
  if (re.test(s)) return s.replace(re, function (_, p1) { return p1 + encodeURIComponent(v); });
  return s + (s ? '&' : '') + k + '=' + encodeURIComponent(v);
}

function blank(v) {
  return v === null || v === undefined || String(v).trim() === '' ||
         String(v) === 'null' || String(v) === 'undefined' || String(v) === '0';
}

/* 兼容服务端两种下发形态：JSON 字符串 / key=value&... 查询串（可能整体编码过一层） */
function fixQuery(q, uid) {
  if (typeof q !== 'string' || q.length < 2 || q.length > 20000) return null;
  if (/^\s*\{/.test(q)) {
    var o;
    try { o = JSON.parse(q); } catch (e) { return null; }
    if (!o || typeof o !== 'object') return null;
    if (!blank(o.userId) && !blank(o.user_id)) return null;
    o.userId = uid;
    return JSON.stringify(o);
  }
  var wrapped = false, s = q;
  if (/%3D|%26|%2F|%3A/i.test(s) && !/(^|&)[A-Za-z0-9_]+=/.test(s)) {
    try { s = decodeURIComponent(s); wrapped = true; } catch (e) { wrapped = false; }
  }
  var cur = qsGet(s, 'userId');
  if (cur === null && qsGet(s, 'user_id') === null) {
    /* 没有任何 userId 键：可能是别种业务串，只在看起来像支付 query 时才补 */
    if (!/orderNum|payWay|payMoney|payPrice|outTradeNo|vBillPay/i.test(s)) return null;
  } else if (!blank(cur)) {
    return null;
  }
  s = qsSet(s, 'userId', uid);
  return wrapped ? encodeURIComponent(s) : s;
}

/* 递归找响应体里所有形如下发 URL 的字段，不写死某一层路径 */
function walk(o, uid) {
  var n = 0;
  if (!o || typeof o !== 'object') return 0;
  for (var k in o) {
    if (!Object.prototype.hasOwnProperty.call(o, k)) continue;
    var v = o[k];
    if (typeof v === 'string') {
      if (!/queryUrl|payUrl|outChainPayUrl|queryString/i.test(k) &&
          !/userId=|orderNum|payWay/i.test(v.slice(0, 400))) continue;
      var nv = fixQuery(v, uid);
      if (nv !== null && nv !== v) { o[k] = nv; n++; }
    } else if (typeof v === 'object') {
      n += walk(v, uid);
    }
  }
  return n;
}

function notify(msg) {
  try { $notify(TAG, '已补 userId', msg); } catch (e) {}
}

function main() {
  var isResponse = (typeof $response !== 'undefined') && $response !== null;

  if (!isResponse) {
    /* ---------- http-request：修 /charge/pay 请求体 ---------- */
    var headers = ($request && $request.headers) || {};
    var body = ($request && $request.body) || '';
    var uid = uidFromToken(headers);
    if (uid) { try { $persistentStore.write(uid, KEY_UID); } catch (e) {} }
    var cur = qsGet(body, 'userId');
    if (uid && (typeof body === 'string') && body.indexOf('=') >= 0 && blank(cur)) {
      var nb = qsSet(body, 'userId', uid);
      if (nb !== body) {
        notify('下单请求 userId 为空，补为 ' + uid);
        $done({ body: nb });
        return;
      }
    }
    $done({});
    return;
  }

  /* ---------- http-response：修 data.queryUrl ---------- */
  var raw = $response.body;
  if (typeof raw !== 'string' || raw.charAt(0) !== '{') { $done({}); return; }
  var uid2 = uidFromToken(($request && $request.headers) || {}) ||
             qsGet(($request && $request.body) || '', 'userId');
  if (blank(uid2)) { try { uid2 = $persistentStore.read(KEY_UID) || ''; } catch (e) {} }
  if (blank(uid2)) { $done({}); return; }
  var j;
  try { j = JSON.parse(raw); } catch (e) { $done({}); return; }
  var n = walk(j, String(uid2));
  if (n > 0) {
    notify('下单响应补 ' + n + ' 处 userId=' + uid2);
    $done({ body: JSON.stringify(j) });
  } else {
    $done({});
  }
}

main();
