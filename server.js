'use strict';
// Relay برای پنل 3x-UI، ساب‌سکریپشن و اینباندهای WebSocket (بدون وابستگی خارجی)
const http = require('http');
const https = require('https');

// ===================== تنظیمات =====================
const PANEL = { scheme: 'https', host: 'nod1.parskhodro.shop', port: 8443 };   // پنل مدیریت
const SUB   = { scheme: 'https', host: 'nod1.parskhodro.shop', port: 2096 };   // سابسکریپشن
const SUB_PATHS = ['/hkgv58zx4pnnqfbz/'];                                       // URI Path ساب

// مسیر WebSocket هر اینباند ← دامنه و پورت همان اینباند
const WS_ROUTES = {
  '/579albx2vgoe6gwogbzm58713hwuqutrnxb84621bqodhry7v49balo': { scheme: 'https', host: 'nod1.parskhodro.shop', port: 2083 }, // trojan
  '/jsjdkebus164648he5464vwoeu546798123h516jekwpry8163g':     { scheme: 'https', host: 'jig.parskhodro.shop',  port: 2087 }, // vless
  '/urkydff5354sajptc4f587mzrphda52479087ifjtspus5f417':      { scheme: 'https', host: 'nod1.parskhodro.shop', port: 2053 }, // vmess
};

// قفل ورود به پنل (اختیاری): متغیر محیطی ACCESS_KEY (فقط حروف و عدد انگلیسی)
const ACCESS_KEY = process.env.ACCESS_KEY || '';
// ===================================================

const lib = t => (t.scheme === 'https' ? https : http);
const baseOf = t => `${t.scheme}://${t.host}:${t.port}`;
const DROP = ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-port', 'x-real-ip', 'forwarded', 'true-client-ip', 'cf-connecting-ip'];

function authorized(req) {
  if (!ACCESS_KEY) return true;
  return (req.headers.cookie || '').split(/;\s*/).includes('wk=' + ACCESS_KEY);
}
function stripGate(headers) {
  if (!headers.cookie) return;
  const c = headers.cookie.split(/;\s*/).filter(x => x && !x.startsWith('wk=')).join('; ');
  if (c) headers.cookie = c; else delete headers.cookie;
}
function upstreamHeaders(req, t) {
  const h = { ...req.headers, host: t.host };
  for (const k of DROP) delete h[k];
  return h;
}

// ---------- HTTP ----------
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const path = u.pathname;

  if (WS_ROUTES[path]) { res.writeHead(404); return res.end('Not Found'); }

  const isSub = SUB_PATHS.some(p => path.startsWith(p));
  const t = isSub ? SUB : PANEL;
  const pub = 'https://' + req.headers.host;

  if (!isSub) {
    if (!authorized(req)) {
      if (u.searchParams.get('key') === ACCESS_KEY) {
        u.searchParams.delete('key');
        res.writeHead(302, {
          Location: u.pathname + u.search,
          'Set-Cookie': `wk=${ACCESS_KEY}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000`,
        });
        return res.end();
      }
      res.writeHead(404); return res.end('Not Found');
    }
  }

  const headers = upstreamHeaders(req, t);
  if (!isSub) stripGate(headers);
  delete headers.connection;
  if (headers.origin) headers.origin = `${t.scheme}://${t.host}`;
  if (headers.referer) headers.referer = headers.referer.replace(pub, `${t.scheme}://${t.host}`);
  if (isSub) headers['accept-encoding'] = 'identity';

  const up = lib(t).request(
    { hostname: t.host, port: t.port, method: req.method, path: req.url, headers, servername: t.host },
    upRes => {
      const h = { ...upRes.headers };
      delete h.connection; delete h['keep-alive']; delete h['transfer-encoding'];

      if (h.location) {
        for (const b of [baseOf(t), `${t.scheme}://${t.host}`]) {
          if (h.location.startsWith(b)) { h.location = pub + h.location.slice(b.length); break; }
        }
      }
      if (h['set-cookie']) h['set-cookie'] = h['set-cookie'].map(c => c.replace(/;\s*Domain=[^;]*/i, ''));

      if (isSub && upRes.statusCode === 200 && /text\/plain/i.test(h['content-type'] || '')) {
        const chunks = [];
        upRes.on('data', c => chunks.push(c));
        upRes.on('end', () => {
          const body = rewriteSub(Buffer.concat(chunks).toString('utf8').trim(), req.headers.host);
          delete h['content-length']; delete h['content-encoding'];
          res.writeHead(200, h);
          res.end(body);
        });
        return;
      }
      res.writeHead(upRes.statusCode, h);
      upRes.pipe(res);
    }
  );
  up.on('error', () => {
    if (!res.headersSent) { res.writeHead(502); res.end('Bad gateway'); } else res.destroy();
  });
  req.pipe(up);
});

// ---------- WebSocket (اینباندها + وضعیت زنده‌ی پنل) ----------
server.on('upgrade', (req, socket, head) => {
  const path = new URL(req.url, 'http://x').pathname;
  let t = WS_ROUTES[path];
  const isPanel = !t;
  if (isPanel) {
    if (!authorized(req)) return socket.destroy();
    t = PANEL;
  }
  const headers = upstreamHeaders(req, t);
  if (isPanel) {
    stripGate(headers);
    if (headers.origin) headers.origin = `${t.scheme}://${t.host}`;
  }

  const up = lib(t).request({ hostname: t.host, port: t.port, method: 'GET', path: req.url, headers, servername: t.host });
  up.on('upgrade', (upRes, upSocket, upHead) => {
    let raw = `HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n`;
    for (let i = 0; i < upRes.rawHeaders.length; i += 2) raw += `${upRes.rawHeaders[i]}: ${upRes.rawHeaders[i + 1]}\r\n`;
    socket.write(raw + '\r\n');
    if (upHead && upHead.length) socket.write(upHead);
    if (head && head.length) upSocket.write(head);
    upSocket.pipe(socket);
    socket.pipe(upSocket);
    const close = () => { socket.destroy(); upSocket.destroy(); };
    upSocket.on('error', close); socket.on('error', close);
    upSocket.on('close', close); socket.on('close', close);
  });
  up.on('response', r => {            // سرور مقصد درخواست WebSocket را رد کرده
    socket.write(`HTTP/1.1 ${r.statusCode} ${r.statusMessage}\r\nConnection: close\r\n\r\n`);
    socket.destroy(); r.resume();
  });
  up.on('error', () => socket.destroy());
  up.end();
});

// ---------- بازنویسی ساب ----------
const b64d = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
const b64e = s => Buffer.from(s, 'utf8').toString('base64');

function rewriteSub(raw, host) {
  const isB64 = !raw.includes('://');
  const text = isB64 ? b64d(raw) : raw;
  const out = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => rewriteLink(l, host)).join('\n');
  return isB64 ? b64e(out) : out;
}
function rewriteLink(link, wh) {
  try {
    if (link.startsWith('vmess://')) {
      const o = JSON.parse(b64d(link.slice(8)));
      if (o.net !== 'ws' || !WS_ROUTES[o.path]) return link;
      Object.assign(o, { add: wh, port: 443, host: wh, sni: wh, tls: 'tls', alpn: 'http/1.1' });
      return 'vmess://' + b64e(JSON.stringify(o));
    }
    const m = link.match(/^(vless|trojan):\/\/([^@]+)@(\[[^\]]+\]|[^:\/?#]+):(\d+)\?([^#]*)(#.*)?$/);
    if (!m) return link;
    const q = new URLSearchParams(m[5]);
    if (q.get('type') !== 'ws' || !WS_ROUTES[q.get('path')]) return link;
    q.set('host', wh); q.set('sni', wh); q.set('alpn', 'http/1.1');
    return `${m[1]}://${m[2]}@${wh}:443?${q.toString()}${m[6] || ''}`;
  } catch {
    return link;
  }
}

process.on('uncaughtException', () => {});
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.listen(process.env.PORT || 10000, '0.0.0.0');
