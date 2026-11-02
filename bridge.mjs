#!/usr/bin/env node
'use strict';

// Local SOCKS5 bridge: exposes 127.0.0.1:LISTEN as a normal SOCKS5 server and
// carries each connection to the remote node over a WSS tunnel. No dependencies.
//
// Use it when the node sits behind an HTTP-only edge (Render and friends) so a
// plain SOCKS5 client cannot reach it directly.
//
// usage:
//   node bridge.mjs --host HOST [--port 443] [--listen 1080] [--user U] [--pass P]
//                   [--path /__tunnel] [--via http://127.0.0.1:8080]
//
//   --via   plain HTTP proxy used to reach the node (when its domain is blocked locally)

import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import http from 'node:http';
import crypto from 'node:crypto';

dns.setDefaultResultOrder('ipv4first');

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  if (i < 0) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

const HOST = String(arg('host', ''));
if (!HOST) {
  console.error('usage: node bridge.mjs --host HOST [--port 443] [--listen 1080] [--user U] [--pass P] [--via URL]');
  process.exit(2);
}
const PORT = Number(arg('port', 443));
const LISTEN = Number(arg('listen', 1080));
const USER = String(arg('user', process.env.PROXY_USER || 'proxyuser'));
const PASS = String(arg('pass', process.env.PROXY_PASS || 'proxypass'));
const PATH = String(arg('path', '/__tunnel'));
const VIA = arg('via', null);
const PLAIN = arg('plain', false) === true;   // ws:// instead of wss:// (local tests only)
const SNI = String(arg('sni', HOST));         // TLS SNI + Host header; set when --host is a raw IP
const DEBUG = process.env.DEBUG_BRIDGE === '1';
const dbg = (...a) => { if (DEBUG) console.error('[bridge]', ...a); };

// ---------- WebSocket framing ----------

function wsFrame(payload, opcode) {
  const len = payload.length;
  let head;
  if (len < 126) { head = Buffer.alloc(2); head[1] = 0x80 | len; }
  else if (len < 65536) { head = Buffer.alloc(4); head[1] = 0x80 | 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[1] = 0x80 | 127; head.writeBigUInt64BE(BigInt(len), 2); }
  head[0] = 0x80 | (opcode || 0x2);
  const mask = crypto.randomBytes(4);
  const out = Buffer.alloc(head.length + 4 + len);
  head.copy(out, 0);
  mask.copy(out, head.length);
  for (let i = 0; i < len; i++) out[head.length + 4 + i] = payload[i] ^ mask[i & 3];
  return out;
}

function wsParser(onBinary, onClose) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const op = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      const maskOff = masked ? 4 : 0;
      if (buf.length < off + maskOff + len) return;
      let payload = buf.subarray(off + maskOff, off + maskOff + len);
      if (masked) {
        const mask = buf.subarray(off, off + 4);
        const copy = Buffer.from(payload);
        for (let i = 0; i < copy.length; i++) copy[i] ^= mask[i & 3];
        payload = copy;
      }
      buf = buf.subarray(off + maskOff + len);
      if (op === 0x8) { onClose && onClose(); return; }
      if (op === 0x9 || op === 0xA) continue;
      onBinary(payload);
    }
  };
}

function wsUpgrade(sock, cb) {
  const key = crypto.randomBytes(16).toString('base64');
  sock.write(
    'GET ' + PATH + ' HTTP/1.1\r\n' +
    'Host: ' + SNI + '\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Key: ' + key + '\r\nSec-WebSocket-Version: 13\r\n\r\n'
  );
  let buf = Buffer.alloc(0);
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    const i = buf.indexOf('\r\n\r\n');
    if (i < 0) return;
    sock.removeListener('data', onData);
    const head = buf.subarray(0, i).toString();
    if (!/^HTTP\/1\.1 101/.test(head)) { cb(new Error(head.split('\r\n')[0])); return; }
    cb(null, buf.subarray(i + 4));
  };
  sock.on('data', onData);
}

// ---------- one tunnelled stream ----------

// The first tunnel after an idle period often dies while the free instance is
// still waking up, so every transport attempt is retried (default 3).
const ATTEMPTS = Number(arg('attempts', 3));

function openStream(target, onData, onError, onClose, attempt) {
  const n = attempt || 1;
  let settled = false;
  let onOpen = () => {};
  const ready = new Promise((resolve) => { onOpen = resolve; });

  const retryOrFail = (why) => {
    if (settled) return;
    settled = true;
    if (n < ATTEMPTS) {
      dbg('retry ' + n + '/' + ATTEMPTS + ' (' + why + ')');
      setTimeout(() => {
        const again = openStream(target, onData, onError, onClose, n + 1);
        again.then((s) => onOpen(s));
      }, 350);
      return;
    }
    onError(new Error(why));
  };

  const attach = (sock) => {
    sock.setNoDelay(true);
    wsUpgrade(sock, (err, rest) => {
      if (err) { try { sock.destroy(); } catch (e) {} retryOrFail('upgrade: ' + err.message); return; }
      if (settled) { try { sock.destroy(); } catch (e) {} return; }
      settled = true;
      dbg('ws upgraded');
      sock.write(wsFrame(Buffer.from(JSON.stringify({ u: USER, p: PASS, host: target.host, port: target.port })), 0x1));
      const parse = wsParser(onData, onClose);
      if (rest && rest.length) parse(rest);
      sock.on('data', parse);
      sock.on('close', onClose);
      sock.on('error', onError);
      onOpen({
        write: (b) => { if (!sock.destroyed) sock.write(wsFrame(b, 0x2)); },
        destroy: () => { try { sock.destroy(); } catch (e) {} },
      });
    });
  };

  if (VIA) {
    const v = new URL(VIA);
    const req = http.request({
      host: v.hostname, port: Number(v.port || 80), method: 'CONNECT',
      path: SNI + ':' + PORT, family: 4,
      headers: v.username
        ? { 'Proxy-Authorization': 'Basic ' + Buffer.from(decodeURIComponent(v.username) + ':' + decodeURIComponent(v.password)).toString('base64') }
        : {},
    });
    req.on('connect', (res, sock) => {
      if (PLAIN) { attach(sock); return; }
      const t = tls.connect({ socket: sock, servername: SNI, ALPNProtocols: ['http/1.1'] });
      t.once('error', (e) => { try { t.destroy(); } catch (e2) {} retryOrFail('tls-via: ' + e.message); });
      t.once('secureConnect', () => attach(t));
    });
    req.on('error', (e) => retryOrFail('via: ' + e.message));
    req.end();
  } else {
    const sock = PLAIN
      ? net.connect({ host: HOST, port: PORT, family: 4 })
      : tls.connect({ host: HOST, port: PORT, servername: SNI, family: 4, ALPNProtocols: ['http/1.1'] });
    sock.once('error', (e) => { try { sock.destroy(); } catch (e2) {} retryOrFail('sock: ' + e.message); });
    sock.once(PLAIN ? 'connect' : 'secureConnect', () => attach(sock));
  }
  return ready;
}
// ---------- local SOCKS5 server ----------

net.createServer((conn) => {
  conn.on('error', () => {});
  let stage = 'greet';
  let buf = Buffer.alloc(0);
  let stream = null;

  conn.on('data', function onData(chunk) {
    if (stage === 'piping') { stream && stream.write(chunk); return; }
    buf = Buffer.concat([buf, chunk]);
    if (stage === 'greet') {
      if (buf.length < 2) return;
      const n = buf[1];
      if (buf.length < 2 + n) return;
      buf = buf.subarray(2 + n);
      conn.write(Buffer.from([0x05, 0x00]));
      stage = 'req';
      return;
    }
    if (stage === 'req') {
      if (buf.length < 4) return;
      const atyp = buf[3];
      let host = '', off = 4;
      if (atyp === 1) { if (buf.length < 10) return; host = Array.from(buf.subarray(4, 8)).join('.'); off = 8; }
      else if (atyp === 3) { const l = buf[4]; if (buf.length < 5 + l + 2) return; host = buf.subarray(5, 5 + l).toString(); off = 5 + l; }
      else { conn.destroy(); return; }
      const port = buf.readUInt16BE(off);
      const rest = buf.subarray(off + 2);
      stage = 'dial';
      openStream({ host, port },
        (d) => conn.write(d),
        () => { try { conn.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); } catch (e) {} conn.destroy(); },
        () => conn.destroy()
      ).then((s) => {
        dbg('stream open');
        stream = s;
        conn.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        stage = 'piping';
        if (rest.length) s.write(rest);
      });
    }
  });
}).listen(LISTEN, '127.0.0.1', () => {
  console.log('local socks5 127.0.0.1:' + LISTEN + '  ->  wss://' + SNI + ':' + PORT + PATH + '  (dial ' + HOST + ')' +
    (VIA ? '  via ' + VIA : ''));
});

// ---------- local HTTP proxy (CONNECT + absolute-URI) on HTTP_LISTEN ----------

const HTTP_LISTEN = Number(arg('http-listen', 0));

if (HTTP_LISTEN) {
  net.createServer((conn) => {
    conn.on('error', () => {});
    let buf = Buffer.alloc(0);
    const onHead = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf('\r\n\r\n');
      if (end < 0) { if (buf.length > 8192) conn.destroy(); return; }
      conn.removeListener('data', onHead);
      const head = buf.subarray(0, end).toString('latin1');
      const rest = buf.subarray(end + 4);
      const lines = head.split('\r\n');
      const m = /^([A-Z]+)\s+(\S+)\s+HTTP\/1\.[01]$/.exec(lines[0] || '');
      if (!m) { conn.end('HTTP/1.1 400 Bad Request\r\n\r\n'); return; }
      const method = m[1];
      const target = m[2];

      let host, port, requestHead;
      if (method === 'CONNECT') {
        const p = target.split(':');
        host = p[0];
        port = Number(p[1] || 443);
        requestHead = null;
      } else if (/^https?:\/\//i.test(target)) {
        const u = new URL(target);
        host = u.hostname;
        port = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
        const restHeaders = lines.slice(1).filter((l) => !/^proxy-connection:/i.test(l));
        requestHead = Buffer.from(
          method + ' ' + (u.pathname + u.search || '/') + ' HTTP/1.1\r\n' + restHeaders.join('\r\n') + '\r\n\r\n'
        );
      } else {
        conn.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        return;
      }

      openStream({ host, port },
        (d) => { try { conn.write(d); } catch (e) {} },
        () => { try { conn.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch (e) {} },
        () => { try { conn.destroy(); } catch (e) {} }
      ).then((s) => {
        if (method === 'CONNECT') { conn.write('HTTP/1.1 200 Connection Established\r\n\r\n'); }
        else if (requestHead) s.write(requestHead);
        if (rest.length) s.write(rest);
        conn.on('data', (d) => s.write(d));
        conn.on('close', () => s.destroy());
      });
    };
    conn.on('data', onHead);
  }).listen(HTTP_LISTEN, '127.0.0.1', () => {
    console.log('local http proxy 127.0.0.1:' + HTTP_LISTEN);
  });
}





