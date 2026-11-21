/*
 * lvcc switch helper (android client edition)
 *
 * Behaviour:
 *   open  https://h5.lvcchong.com/__lvcc_switch__?mobile=<n>   -> remember n
 *   then  /getUnionInfo                                          -> rewrite to /registerOrLoginUser?mobile=<n>
 *         https://h5.lvcchong.com/__lvcc_switch__?mobile=off     -> clear
 *
 * Install (client 1.4.0):
 *   Settings -> Script -> + -> URL(s): *lvcchong.com*  -> Type: Remote URL
 *   Paste this file's raw URL -> save -> enable the master script switch
 *
 * Injected signature: onRequest(context, request)
 *   context = { scriptName, os, session, deviceId, env }
 *   request = { host, url, path, queries, headers, method, body, rawBody }
 * Returning request applies the changes; path/queries/headers/method/body are writable.
 */

var KEY = 'lvccMobile';
var MOBILE_RE = /^1\d{10}$/;

function getMobile(context) {
  var m = '';
  try { if (context.session) m = context.session[KEY] || ''; } catch (e) {}
  if (!m) { try { if (context.env) m = context.env[KEY] || ''; } catch (e) {} }
  return String(m || '');
}

function setMobile(context, m) {
  try { if (context.session) context.session[KEY] = m; } catch (e) {}
  try { if (context.env) context.env[KEY] = m; } catch (e) {}
}

async function onRequest(context, request) {
  try {
    var host = String(request.host || '');
    var path = String(request.path || '');

    // (1) switch endpoint on any host
    if (path.indexOf('/__lvcc_switch__') >= 0) {
      var q = request.queries || {};
      var raw = String(q['mobile'] || q['phone'] || '');
      if (raw === 'off' || raw === '0') {
        setMobile(context, '');
        console.log('[lvcc] cleared');
        return request;
      }
      if (MOBILE_RE.test(raw)) {
        setMobile(context, raw);
        console.log('[lvcc] target -> ' + raw);
      } else {
        console.log('[lvcc] bad number: ' + raw);
      }
      return request;
    }

    // (2) only these two endpoints, everything else passes through
    if (host.indexOf('appapi.lvcchong.com') < 0) return request;
    if (!/^\/(getUnionInfo|registerOrLoginUser)/.test(path)) return request;

    var mobile = getMobile(context);
    if (!MOBILE_RE.test(mobile)) return request;

    request.path = '/registerOrLoginUser';
    request.queries = {
      mobile: mobile,
      ownerId: '0',
      entryType: '5',
      registerOrBind: '1',
      validateType: '3',
      checkDataValue: ''
    };

    console.log('[lvcc] rewrite -> ' + mobile + ' (was ' + path + ')');
    return request;
  } catch (e) {
    console.log('[lvcc] error: ' + e);
    return request;
  }
}

async function onResponse(context, request, response) {
  return response;
}
