/**
 * lvcc_bind_identity.js —— 把「当前微信/支付宝身份」一次性写进目标手机号账号
 *
 * 为什么需要它（实测结论，probe_token_userid_decouple.js）：
 *   服务端所有业务接口一律按 token 里的 userId 定位账号，请求体里的 userId 被忽略。
 *   A.token + B.userId 返回的仍是 A 的手机号 / A 的积分 / A 的 openid。
 *   => 换号后 token 是目标号的，服务端就按目标号反查 openid，
 *      而目标号绑的是别的微信，微信支付就弹「下单账号与支付账号不一致」。
 *      券、余额、openid 三者同绑在一张 token 上，代理层拆不开。
 *
 * 根解：让目标号的 openid 变成「当前这台手机上的微信」。
 *   小程序自带 /appBaseApi/user/bindPhone：
 *     POST { phone, randCode, ownerId }  + header token=<当前微信原生会话票>
 *     成功返回 data.userToken/refreshToken/userId/chargeTypeTag（目标号的新票）
 *   这一步把当前微信的 openid 合并进目标账号。之后任何端切到该号，
 *   微信支付 / 支付宝支付都不再和目标微信身份冲突。
 *
 * 三条哨兵（点链接时 VPN 必须开）：
 *   https://h5.lvcchong.com/__lvcc_bind__?mobile=13971175530
 *       -> 给该号发绑定短信验证码，并把号码记进本机
 *   https://h5.lvcchong.com/__lvcc_bind__?code=123456
 *       -> 用记下的号码 + 当前微信原生票提交 bindPhone
 *   https://h5.lvcchong.com/__lvcc_bind__?status=1
 *       -> 查当前微信原生票绑定的 openid（诊断）
 *   https://h5.lvcchong.com/__lvcc_bind__?reset=1
 *       -> 清空本机记录
 *
 * 前置（只做一次）：
 *   1) 临时关掉「换号模块」的开关，删掉驴充充小程序重开，
 *      让它走原生 /getUnionInfo 用当前微信登录。
 *   2) 本脚本的 http-response 规则会抓下这次响应的 userToken/openid 存到本机。
 *   3) 之后点上面两条链接完成绑定，再开回换号模块。
 *
 * 依赖：Shadowrocket / Stash / Surge 的 $persistentStore、$httpClient、$notify。
 *       Quantumult X 用 $prefs，同样兼容。
 */
var KEY_WX_TOKEN = 'lvcc_bind_wx_token';
var KEY_WX_OPENID = 'lvcc_bind_wx_openid';
var KEY_WX_UID = 'lvcc_bind_wx_userid';
var KEY_MOBILE = 'lvcc_bind_mobile';
var KEY_LAST = 'lvcc_bind_last_result';

var BASE = 'https://appapi.lvcchong.com';
var CHANNEL = '?channelMessage=' + encodeURIComponent('LVCC-WP-PH_15.0.1_Tencent-G9');
var UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.74(0x18004a30) NetType/WIFI Language/zh_CN';

function kvGet(k) {
  var v = '';
  try { if (typeof $persistentStore !== 'undefined') v = $persistentStore.read(k) || ''; } catch (e) {}
  try { if (!v && typeof $prefs !== 'undefined') v = $prefs.valueForKey(k) || ''; } catch (e) {}
  return String(v || '');
}
function kvSet(k, v) {
  try { if (typeof $persistentStore !== 'undefined') $persistentStore.write(String(v), k); } catch (e) {}
  try { if (typeof $prefs !== 'undefined') $prefs.setValueForKey(String(v), k); } catch (e) {}
}
function notify(sub, msg) {
  try { if (typeof $notify !== 'undefined') $notify('驴充充绑身份', sub, msg); } catch (e) {}
}
function enc(o) {
  var a = [];
  for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) {
    a.push(encodeURIComponent(k) + '=' + encodeURIComponent(o[k] == null ? '' : o[k]));
  }
  return a.join('&');
}
function getParam(url, name) {
  var m = url.match(new RegExp('[?&]' + name + '=([^&#]*)'));
  if (!m) return '';
  try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; }
}
function post(path, form, token, cb) {
  var headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA };
  if (token) headers.token = token;
  var opt = { url: BASE + path + CHANNEL, headers: headers, body: enc(form) };
  try {
    $httpClient.post(opt, function (err, resp, data) {
      if (err) return cb('NET ' + String(err));
      var j;
      try { j = JSON.parse(data); } catch (e) { j = { _raw: String(data).slice(0, 220) }; }
      cb(null, j);
    });
  } catch (e) { cb('EXC ' + e.message); }
}
function html(title, lines) {
  var body = '<meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<div style="font:16px/1.7 -apple-system,sans-serif;padding:24px;color:#222">'
    + '<h2 style="margin:0 0 12px">' + title + '</h2><pre style="white-space:pre-wrap;word-break:break-all;'
    + 'background:#f5f5f7;padding:14px;border-radius:10px;font:13px/1.6 monospace">'
    + lines.join('\n').replace(/</g, '&lt;') + '</pre></div>';
  return { response: { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' }, body: body } };
}
function finish(title, lines) {
  kvSet(KEY_LAST, lines.join(' | '));
  notify(title, lines.join(' '));
  try { $done(html(title, lines)); } catch (e) { try { $done({}); } catch (e2) {} }
}

function handleSentinel(url) {
  if (getParam(url, 'reset')) {
    [KEY_WX_TOKEN, KEY_WX_OPENID, KEY_WX_UID, KEY_MOBILE, KEY_LAST].forEach(function (k) { kvSet(k, ''); });
    return finish('已清空', ['本机绑定记录已全部清除']);
  }

  var token = kvGet(KEY_WX_TOKEN);
  if (getParam(url, 'status')) {
    var lines = [
      '原生微信票: ' + (token ? '已抓到(' + token.length + 'B)' : '未抓到'),
      'openid: ' + (kvGet(KEY_WX_OPENID) || '(无)'),
      '原生 userId: ' + (kvGet(KEY_WX_UID) || '(无)'),
      '待绑手机号: ' + (kvGet(KEY_MOBILE) || '(无)'),
      '上次结果: ' + (kvGet(KEY_LAST) || '(无)')
    ];
    if (!token) return finish('未就绪', lines.concat(['先关换号模块，删小程序重开一次']));
    return post('/appBaseApi/user/getUserOpenIdByType', { type: '3' }, token, function (e, j) {
      lines.push('查 type=3: ' + (e || JSON.stringify(j).slice(0, 240)));
      finish('身份状态', lines);
    });
  }

  var mobile = getParam(url, 'mobile');
  if (mobile && /^1\d{10}$/.test(mobile)) kvSet(KEY_MOBILE, mobile);
  var code = getParam(url, 'code');

  // 第一步：只发短信，不改任何绑定
  if (!code) {
    var m = kvGet(KEY_MOBILE);
    if (!/^1\d{10}$/.test(m)) return finish('缺参数', ['先点 ?mobile=11位手机号']);
    return post('/appBaseApi/codeVerifySendRegisterSms',
      { mobile: m, ownerId: '0', time: String(Date.now()) }, token,
      function (e, j) {
        var ok = !e && j && (j.success === true || j.code === 200);
        finish(ok ? '验证码已发送' : '发码失败', [
          '手机号: ' + m,
          '返回: ' + (e || JSON.stringify(j).slice(0, 260)),
          ok ? '收到短信后点 ?code=6位验证码' : '可改用小程序「我的→绑定手机号」页面发码'
        ]);
      });
  }

  // 第二步：提交绑定。必须用当前微信原生票，不能用换号模块签的免密票。
  var m2 = kvGet(KEY_MOBILE);
  if (!/^1\d{10}$/.test(m2)) return finish('缺手机号', ['先点 ?mobile=11位手机号']);
  if (!token) return finish('缺少原生微信票', [
    '关掉换号模块 → 删小程序重开 → 让 /getUnionInfo 走一次',
    '本模块 http-response 规则会自动抓票，再回来点 ?code=' + code
  ]);

  return post('/appBaseApi/user/bindPhone',
    { phone: m2, randCode: code, ownerId: '0' }, token,
    function (e, j) {
      var ok = !e && j && j.success === true && j.data && j.data.userToken;
      var lines = [
        '手机号: ' + m2,
        '返回: ' + (e || JSON.stringify(j).slice(0, 320)),
        '原生 openid: ' + (kvGet(KEY_WX_OPENID) || '(未记录)')
      ];
      if (ok) {
        lines.push('新 userId: ' + (j.data.userId || '?'));
        lines.push('绑定完成：删小程序重开，再开回换号模块');
        kvSet(KEY_MOBILE, '');
      } else {
        lines.push('未成功：验证码错/已绑定别的微信/票据过期都会走到这里');
      }
      finish(ok ? '绑定成功' : '绑定未成功', lines);
    });
}

// http-response：抓当前微信原生登录返回的票，这是整个方案的凭证来源。
function handleResponse(url, body) {
  if (!/\/getUnionInfo(\?|$)/.test(url)) { try { $done({}); } catch (e) {} return; }
  var j = null;
  try { j = JSON.parse(body); } catch (e) {}
  var d = j && j.data ? j.data : null;
  if (d && d.userToken) {
    kvSet(KEY_WX_TOKEN, d.userToken);
    if (d.openid) kvSet(KEY_WX_OPENID, d.openid);
    if (d.userId) kvSet(KEY_WX_UID, d.userId);
    notify('已抓到原生微信票', 'openid=' + (d.openid || '?') + ' 可开始绑定');
  }
  try { $done({}); } catch (e) {}
}

(function main() {
  var req = (typeof $request !== 'undefined') ? $request : null;
  var resp = (typeof $response !== 'undefined') ? $response : null;
  var url = (req && req.url) || '';

  if (resp) return handleResponse(url, resp.body || '');
  if (/__lvcc_bind__/.test(url)) return handleSentinel(url);
  // 其它请求一律不动：本模块不改写任何登录或支付请求，与换号模块互不干扰。
  try { $done({}); } catch (e) {}
})();
