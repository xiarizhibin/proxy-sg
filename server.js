'use strict';

// Dual-protocol proxy for HTTP(S) + SOCKS5, single Node process, no framework.
//
//   PORT        HTTP/HTTPS forward proxy  (CONNECT + absolute-URI)  + /__health + /__tunnel (WS)
//   SOCKS_PORT  optional native SOCKS5 listener for hosts that expose raw TCP (VPS / bare metal)
//
// Auth: HTTP  -> Proxy-Authorization: Basic
//       SOCKS -> RFC1929 username/password
// Credentials come from PROXY_USER / PROXY_PASS.

const http = require('http');
const net = require('net');
const dns = require('dns');
const { WebSocketServer } = require('ws');

// IPv4-only egress: the node must present (and dial) IPv4.
// 'ipv4first' keeps A records ahead of AAAA for every lookup in this process,
// and every socket below is created with family: 4 as a belt-and-braces guard.
dns.setDefaultResultOrder('ipv4first');

const PORT = Number(process.env.PORT || 8080);
const SOCKS_PORT = process.env.SOCKS_PORT ? Number(process.env.SOCKS_PORT) : 0;
const USER = process.env.PROXY_USER || 'proxyuser';
const PASS = process.env.PROXY_PASS || 'proxypass';
const ENABLE_TUNNEL = (process.env.ENABLE_TUNNEL || 'true') !== 'false';
const CONNECT_TIMEOUT = Number(process.env.CONNECT_TIMEOUT_MS || 15000);

const startedAt = Date.now();
const stats = { http: 0, connect: 0, socks: 0, tunnel: 0, denied: 0, bytesUp: 0, bytesDown: 0 };

// ---------- helpers ----------

function authOk(header) {
  if (!header) return false;
  const m = /^Basic\s+(.+)$/i.exec(header.trim());
  if (!m) return false;
  let raw;
  try { raw = Buffer.from(m[1], 'base64').toString('utf8'); } catch (e) { return false; }
  const i = raw.indexOf(':');
  if (i < 0) return false;
  return raw.slice(0, i) === USER && raw.slice(i + 1) === PASS;
}

function socksAuthOk(u, p) {
  return u === USER && p === PASS;
}

// block obvious internal targets so the proxy cannot be used to poke the
// platform network (SSRF hygiene). Add PRIVATE_ALLOW=true to disable.
const ALLOW_PRIVATE = process.env.PRIVATE_ALLOW === 'true';
function blockedTarget(host) {
  if (ALLOW_PRIVATE) return false;
  const h = String(host).toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal')) return true;
  if (/^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (h === '::1' || /^f[cd][0-9a-f]{2}:/.test(h) || /^fe80:/.test(h)) return true;
  return false;
}

function destOf(urlLike) {
  // "http://host:port/..." -> { host, port }
  try {
    const u = new URL(urlLike);
    return { host: u.hostname, port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)) };
  } catch (e) {
    return null;
  }
}

function dial(host, port, onReady, onError) {
  // family: 4 -> IPv4 only, never fall back to an AAAA record
  const sock = net.connect({ host, port, family: 4, autoSelectFamily: false });
  const timer = setTimeout(() => { sock.destroy(); onError('connect-timeout'); }, CONNECT_TIMEOUT);
  sock.once('connect', () => { clearTimeout(timer); onReady(sock); });
  sock.once('error', (e) => { clearTimeout(timer); onError(e.code || e.message); });
  return sock;
}

function pipe(a, b) {
  a.on('data', (d) => { stats.bytesDown += d.length; if (!b.write(d)) a.pause(); });
  b.on('drain', () => a.resume());
  b.on('data', (d) => { stats.bytesUp += d.length; if (!a.write(d)) b.pause(); });
  a.on('drain', () => b.resume());
  const end = () => { a.destroy(); b.destroy(); };
  a.on('close', end); b.on('close', end);
  a.on('error', end); b.on('error', end);
}

// ---------- HTTP / HTTPS proxy ----------

const server = http.createServer((req, res) => {
  const url = req.url || '/';

  if (url.startsWith('/__health')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      up: Math.round((Date.now() - startedAt) / 1000),
      http: stats.http,
      connect: stats.connect,
      socks: stats.socks,
      tunnels: stats.tunnel,
      denied: stats.denied,
      bytesUp: stats.bytesUp,
      bytesDown: stats.bytesDown,
      socksPort: SOCKS_PORT || null,
      egress: 'ipv4',
    }, null, 1));
    return;
  }

  if (!authOk(req.headers['proxy-authorization'])) {
    stats.denied++;
    res.writeHead(407, {
      'Proxy-Authenticate': 'Basic realm="proxy"',
      'Content-Type': 'text/plain',
    });
    res.end('proxy authentication required\n');
    return;
  }

  // absolute-URI request: forward to origin, stream the response back
  const dest = destOf(url.startsWith('http') ? url : 'http://' + (req.headers.host || '') + url);
  if (!dest || blockedTarget(dest.host)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('target not allowed\n');
    return;
  }
  stats.http++;

  const headers = Object.assign({}, req.headers);
  delete headers['proxy-authorization'];
  delete headers['proxy-connection'];

  const upstream = http.request({ host: dest.host, port: dest.port, method: req.method, path: url, headers, family: 4 }, (up) => {
    res.writeHead(up.statusCode || 502, up.headers);
    up.pipe(res);
  });
  upstream.on('error', () => { try { res.writeHead(502); res.end('bad gateway\n'); } catch (e) {} });
  req.pipe(upstream);
});

server.on('connect', (req, socket, head) => {
  socket.on('error', () => {});
  if (!authOk(req.headers['proxy-authorization'])) {
    stats.denied++;
    socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\n\r\n');
    return;
  }
  const hp = String(req.url || '').split(':');
  const host = hp[0];
  const port = Number(hp[1] || 443);
  if (!host || blockedTarget(host)) {
    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    return;
  }
  stats.connect++;
  socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  dial(host, port, (up) => {
    if (head && head.length) up.write(head);
    pipe(socket, up);
  }, () => { try { socket.destroy(); } catch (e) {} });
});

// ---------- WebSocket tunnel (lets a local SOCKS5 bridge use this node) ----------

if (ENABLE_TUNNEL) {
  const wss = new WebSocketServer({ server, path: '/__tunnel', perMessageDeflate: false });
  wss.on('connection', (ws) => {
    let sock = null;
    let ready = false;
    const queue = [];
    ws.on('message', (data) => {
      const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (!ready) {
        ready = true;
        let spec;
        try { spec = JSON.parse(b.toString('utf8')); } catch (e) { ws.close(); return; }
        if (spec.u !== USER || spec.p !== PASS || !spec.host || blockedTarget(spec.host)) { ws.close(); return; }
        stats.tunnel++;
        sock = dial(spec.host, Number(spec.port || 443), (s) => {
          for (const c of queue) s.write(c);
          queue.length = 0;
          s.on('data', (d) => { if (ws.readyState === 1) ws.send(d); });
          s.on('close', () => { try { ws.close(); } catch (e) {} });
          s.on('error', () => { try { ws.close(); } catch (e) {} });
        }, () => ws.close());
        return;
      }
      if (sock && !sock.destroyed) sock.write(b); else if (queue.length < 64) queue.push(b);
    });
    ws.on('close', () => { if (sock) sock.destroy(); });
    ws.on('error', () => { if (sock) sock.destroy(); });
  });
}

// ---------- native SOCKS5 (only where raw TCP is exposed) ----------

function socks5(conn, head) {
  let stage = 'greet';
  let buf = head || Buffer.alloc(0);
  let user = '', pass = '';

  const send = (b) => conn.write(b);
  const fail = () => { try { conn.destroy(); } catch (e) {} };

  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (stage === 'greet') {
        if (buf.length < 2) return;
        const n = buf[1];
        if (buf.length < 2 + n) return;
        buf = buf.subarray(2 + n);
        send(Buffer.from([0x05, 0x02])); // username/password
        stage = 'auth';
      } else if (stage === 'auth') {
        if (buf.length < 2) return;
        if (buf[0] !== 1) return fail();
        const ul = buf[1];
        if (buf.length < 2 + ul + 1) return;
        const pl = buf[2 + ul];
        if (buf.length < 2 + ul + 1 + pl) return;
        user = buf.subarray(2, 2 + ul).toString();
        pass = buf.subarray(3 + ul, 3 + ul + pl).toString();
        buf = buf.subarray(3 + ul + pl);
        if (!socksAuthOk(user, pass)) { send(Buffer.from([0x01, 0x01])); return fail(); }
        send(Buffer.from([0x01, 0x00]));
        stage = 'req';
      } else if (stage === 'req') {
        if (buf.length < 4) return;
        const atyp = buf[3];
        let host = '', off = 4;
        if (atyp === 1) { if (buf.length < 10) return; host = Array.from(buf.subarray(4, 8)).join('.'); off = 8; }
        else if (atyp === 3) { const l = buf[4]; if (buf.length < 5 + l + 2) return; host = buf.subarray(5, 5 + l).toString(); off = 5 + l; }
        else if (atyp === 4) {
          if (buf.length < 4 + 16 + 2) return;
          const seg = []; for (let i = 0; i < 8; i++) seg.push(buf.readUInt16BE(4 + i * 2).toString(16));
          host = seg.join(':'); off = 20;
        } else return fail();
        const port = buf.readUInt16BE(off);
        const rest = buf.subarray(off + 2);
        if (blockedTarget(host)) { send(Buffer.from([0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); return fail(); }
        stats.socks++;
        dial(host, port, (up) => {
          send(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          conn.removeListener('data', onData);
          if (rest.length) up.write(rest);
          pipe(conn, up);
        }, () => { send(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); fail(); });
        stage = 'done';
        return;
      } else return;
    }
  };
  conn.on('data', onData);
  conn.on('error', () => {});
  if (buf.length) onData(Buffer.alloc(0));
}

if (SOCKS_PORT) {
  net.createServer((c) => {
    c.once('data', (d) => socks5(c, d));
    c.on('error', () => {});
  }).listen(SOCKS_PORT, '0.0.0.0', () => console.log('socks5 on ' + SOCKS_PORT));
}

server.listen(PORT, '0.0.0.0', () => console.log('http proxy on ' + PORT));



