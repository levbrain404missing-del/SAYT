/**
 * Временный демо-сайт: регистрация / вход / восстановление доступа.
 * Без внешних зависимостей: node:http + node:sqlite + node:crypto.
 *
 * Пароли НИКОГДА не хранятся и не логируются в открытом виде:
 * хранится только scrypt-хеш с индивидуальной солью.
 */
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import net from 'node:net';
import { DatabaseSync } from 'node:sqlite';

// ---------------------------------------------------------------- конфигурация
const PORT = Number(process.env.PORT || 3100);
const HOST = process.env.HOST || '127.0.0.1';
const DB_PATH = process.env.DB_PATH || '/var/lib/stub-auth/app.db';
const MAIL_LOG = process.env.MAIL_LOG || '/var/lib/stub-auth/mail.log';
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-insecure-secret';
const SECURE_COOKIES = process.env.SECURE_COOKIES !== '0';
// Показывать ссылку восстановления прямо на странице (нужно, пока нет SMTP).
const SHOW_RESET_LINK = process.env.SHOW_RESET_LINK !== '0';
const SITE_NAME = process.env.SITE_NAME || 'Demo Access';

const SMTP = {
  host: process.env.SMTP_HOST || '',
  port: Number(process.env.SMTP_PORT || 465),
  user: process.env.SMTP_USER || '',
  pass: process.env.SMTP_PASS || '',
  from: process.env.SMTP_FROM || process.env.SMTP_USER || '',
};

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;   // 7 дней
const RESET_TTL_MS = 30 * 60 * 1000;              // 30 минут
const SCRYPT = { N: 32768, r: 8, p: 1, keylen: 32 };

// ---------------------------------------------------------------------- хранилище
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    pass_hash   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS resets (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
  );
`);

const q = {
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare(
    'INSERT INTO users (name, email, pass_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
  ),
  updatePass: db.prepare('UPDATE users SET pass_hash = ?, updated_at = ? WHERE id = ?'),
  updateEmail: db.prepare('UPDATE users SET email = ?, updated_at = ? WHERE id = ?'),
  insertSession: db.prepare(
    'INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
  ),
  sessionByHash: db.prepare('SELECT * FROM sessions WHERE token_hash = ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  insertReset: db.prepare(
    'INSERT INTO resets (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
  ),
  resetByHash: db.prepare('SELECT * FROM resets WHERE token_hash = ?'),
  useReset: db.prepare('UPDATE resets SET used_at = ? WHERE token_hash = ?'),
  invalidateResets: db.prepare('UPDATE resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL'),
  gcSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
  gcResets: db.prepare('DELETE FROM resets WHERE expires_at < ?'),
};

setInterval(() => {
  try {
    q.gcSessions.run(Date.now());
    q.gcResets.run(Date.now() - 24 * 60 * 60 * 1000);
  } catch { /* не критично */ }
}, 60 * 60 * 1000).unref();

// --------------------------------------------------------------------- крипто
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(password, salt, SCRYPT.keylen, {
    N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 256 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${dk.toString('base64')}`;
}

function verifyPassword(password, stored) {
  try {
    const [algo, N, r, p, saltB64, hashB64] = String(stored).split('$');
    if (algo !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const dk = crypto.scryptSync(password, salt, expected.length, {
      N: Number(N), r: Number(r), p: Number(p), maxmem: 256 * 1024 * 1024,
    });
    return dk.length === expected.length && crypto.timingSafeEqual(dk, expected);
  } catch {
    return false;
  }
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomToken = () => crypto.randomBytes(32).toString('base64url');

function csrfFor(seed) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(`csrf:${seed}`).digest('base64url');
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// ---------------------------------------------------------------- rate limiting
const buckets = new Map();
function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || b.resetAt < now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { ok: true, retryAfter: 0 };
  }
  b.count += 1;
  if (b.count > limit) return { ok: false, retryAfter: Math.ceil((b.resetAt - now) / 1000) };
  return { ok: true, retryAfter: 0 };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (v.resetAt < now) buckets.delete(k);
}, 10 * 60 * 1000).unref();

// --------------------------------------------------------------------- почта
function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

async function smtpSend({ to, subject, text }) {
  if (!SMTP.host || !SMTP.user || !SMTP.pass) throw new Error('SMTP не настроен');
  const implicitTls = SMTP.port === 465;
  const socket = implicitTls
    ? tls.connect({ host: SMTP.host, port: SMTP.port, servername: SMTP.host })
    : net.connect({ host: SMTP.host, port: SMTP.port });

  let sock = socket;
  let buffer = '';
  const waiters = [];

  const attach = (s) => {
    s.setEncoding('utf8');
    s.on('data', (chunk) => {
      buffer += chunk;
      let idx;
      // Ответ закончен, когда пришла строка вида "250 text" (пробел, а не дефис, после кода).
      while ((idx = buffer.indexOf('\r\n')) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        if (/^\d{3} /.test(line)) {
          const w = waiters.shift();
          if (w) w.resolve(line);
        }
      }
    });
  };
  attach(sock);

  const expect = (codes) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('SMTP timeout')), 20000);
    waiters.push({
      resolve: (line) => {
        clearTimeout(timer);
        const code = Number(line.slice(0, 3));
        if (!codes.includes(code)) reject(new Error(`SMTP: ожидался ${codes}, получен "${line}"`));
        else resolve(line);
      },
    });
  });
  const send_ = (line) => new Promise((res, rej) => sock.write(line + '\r\n', (e) => (e ? rej(e) : res())));

  await new Promise((res, rej) => {
    sock.once(implicitTls ? 'secureConnect' : 'connect', res);
    sock.once('error', rej);
  });
  await expect([220]);
  await send_('EHLO stub-auth'); await expect([250]);

  if (!implicitTls) {
    await send_('STARTTLS'); await expect([220]);
    sock = tls.connect({ socket, servername: SMTP.host });
    await new Promise((res, rej) => { sock.once('secureConnect', res); sock.once('error', rej); });
    buffer = '';
    attach(sock);
    await send_('EHLO stub-auth'); await expect([250]);
  }

  await send_('AUTH LOGIN'); await expect([334]);
  await send_(Buffer.from(SMTP.user).toString('base64')); await expect([334]);
  await send_(Buffer.from(SMTP.pass).toString('base64')); await expect([235]);
  await send_(`MAIL FROM:<${SMTP.from}>`); await expect([250]);
  await send_(`RCPT TO:<${to}>`); await expect([250, 251]);
  await send_('DATA'); await expect([354]);
  const headers = [
    `From: ${SITE_NAME} <${SMTP.from}>`,
    `To: <${to}>`,
    `Subject: =?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(text).toString('base64').replace(/(.{76})/g, '$1\r\n'),
  ].join('\r\n');
  await send_(headers);
  await send_('.'); await expect([250]);
  await send_('QUIT').catch(() => {});
  sock.end();
}

async function sendMail({ to, subject, text }) {
  const record = `[${new Date().toISOString()}] to=${to} subject="${subject}"\n${text}\n${'-'.repeat(60)}\n`;
  try { fs.appendFileSync(MAIL_LOG, record); } catch (e) { log('mail.log недоступен:', e.message); }
  if (!SMTP.host) { log(`письмо НЕ отправлено (SMTP не настроен), записано в ${MAIL_LOG}`); return false; }
  try {
    await smtpSend({ to, subject, text });
    log(`письмо отправлено: ${to}`);
    return true;
  } catch (e) {
    log('ошибка отправки письма:', e.message);
    return false;
  }
}

// -------------------------------------------------------------------- хелперы
const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const EMAIL_RE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;
const normEmail = (e) => String(e || '').trim().toLowerCase();

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xff || req.socket.remoteAddress || 'unknown';
}

async function readBody(req, limit = 16 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function cookie(name, value, maxAgeSec) {
  const bits = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/', 'HttpOnly', 'SameSite=Lax',
    `Max-Age=${maxAgeSec}`,
  ];
  if (SECURE_COOKIES) bits.push('Secure');
  return bits.join('; ');
}

function currentUser(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  const row = q.sessionByHash.get(sha256(token));
  if (!row) return null;
  if (row.expires_at < Date.now()) { q.deleteSession.run(row.token_hash); return null; }
  return q.userById.get(row.user_id) || null;
}

function send(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'X-Frame-Options': 'DENY',
    ...extraHeaders,
  });
  res.end(body);
}

const redirect = (res, to, extraHeaders = {}) =>
  send(res, 303, '', { Location: to, ...extraHeaders });

// -------------------------------------------------------------------- вёрстка
const CSS = `
:root{
  --bg:#07070c; --card:rgba(22,22,34,.72); --line:rgba(255,255,255,.09);
  --txt:#ececf4; --dim:#9b9bb4; --acc1:#7c5cff; --acc2:#19d2ff;
  --ok:#2fd27c; --err:#ff5f6d;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; font-family:ui-sans-serif,-apple-system,"Segoe UI",Inter,Roboto,Arial,sans-serif;
  color:var(--txt); background:var(--bg); -webkit-font-smoothing:antialiased;
  display:flex; align-items:center; justify-content:center; padding:28px 18px;
  background-image:
    radial-gradient(760px 520px at 12% -8%, rgba(124,92,255,.30), transparent 62%),
    radial-gradient(680px 460px at 96% 4%, rgba(25,210,255,.20), transparent 60%),
    radial-gradient(900px 620px at 50% 118%, rgba(124,92,255,.14), transparent 62%);
}
.wrap{width:100%; max-width:452px}
.brand{display:flex; align-items:center; gap:11px; margin:0 0 20px 4px}
.logo{width:38px;height:38px;border-radius:11px;flex:0 0 auto;
  background:linear-gradient(135deg,var(--acc1),var(--acc2));
  box-shadow:0 8px 26px rgba(124,92,255,.42);
  display:grid;place-items:center;font-weight:800;color:#0b0b14;font-size:17px}
.brand b{font-size:17px;letter-spacing:.2px}
.brand span{display:block;font-size:12px;color:var(--dim);font-weight:400;margin-top:1px}
.card{
  background:var(--card); border:1px solid var(--line); border-radius:20px;
  padding:28px 26px 26px; backdrop-filter:blur(22px) saturate(1.3);
  box-shadow:0 26px 70px rgba(0,0,0,.6), inset 0 1px 0 rgba(255,255,255,.06);
  animation:rise .4s cubic-bezier(.2,.8,.2,1) both;
}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
h1{margin:0 0 6px; font-size:23px; letter-spacing:-.2px}
.sub{margin:0 0 22px; color:var(--dim); font-size:14px; line-height:1.5}
label{display:block; font-size:12.5px; color:var(--dim); margin:0 0 7px; font-weight:500}
.f{margin-bottom:15px}
input{
  width:100%; padding:13px 14px; border-radius:12px; font-size:15px; color:var(--txt);
  background:rgba(255,255,255,.045); border:1px solid var(--line);
  transition:border-color .16s, box-shadow .16s, background .16s; outline:none;
}
input::placeholder{color:#64647c}
input:focus{border-color:rgba(124,92,255,.75); background:rgba(255,255,255,.07);
  box-shadow:0 0 0 4px rgba(124,92,255,.17)}
.pw{position:relative}
.pw input{padding-right:92px}
.pw button{position:absolute; right:7px; top:7px; height:34px; padding:0 11px; border:0;
  border-radius:9px; background:rgba(255,255,255,.07); color:var(--dim); cursor:pointer; font-size:12px}
.pw button:hover{color:var(--txt); background:rgba(255,255,255,.12)}
.meter{height:4px;border-radius:99px;background:rgba(255,255,255,.08);margin-top:9px;overflow:hidden}
.meter i{display:block;height:100%;width:0;border-radius:99px;transition:width .25s, background .25s}
.hint{font-size:11.5px;color:var(--dim);margin-top:7px}
button.go{
  width:100%; margin-top:8px; padding:14px 16px; border:0; border-radius:12px; cursor:pointer;
  font-size:15px; font-weight:650; color:#0b0b14; letter-spacing:.1px;
  background:linear-gradient(135deg,var(--acc1),var(--acc2)); background-size:160% 160%;
  box-shadow:0 12px 30px rgba(124,92,255,.34); transition:transform .14s, box-shadow .2s, background-position .35s;
}
button.go:hover{background-position:100% 0; transform:translateY(-1px); box-shadow:0 16px 38px rgba(124,92,255,.44)}
button.go:active{transform:translateY(0)}
.alt{margin:19px 0 0; text-align:center; font-size:13.5px; color:var(--dim)}
.alt a, a.link{color:#b6a6ff; text-decoration:none}
.alt a:hover, a.link:hover{text-decoration:underline}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:7px}
.row label{margin:0}
.msg{border-radius:12px; padding:12px 14px; font-size:13.5px; line-height:1.5; margin-bottom:18px;
  border:1px solid transparent; word-break:break-word}
.msg.err{background:rgba(255,95,109,.11); border-color:rgba(255,95,109,.33); color:#ffb3b9}
.msg.ok{background:rgba(47,210,124,.1); border-color:rgba(47,210,124,.3); color:#95eebb}
.msg code{display:block;margin-top:8px;font-size:11.5px;color:#cfd2ff;
  background:rgba(0,0,0,.4);padding:9px 10px;border-radius:8px;word-break:break-all}
.who{display:flex;align-items:center;gap:14px;margin-bottom:20px}
.ava{width:54px;height:54px;border-radius:16px;flex:0 0 auto;display:grid;place-items:center;
  font-weight:700;font-size:20px;color:#0b0b14;background:linear-gradient(135deg,var(--acc2),var(--acc1));
  box-shadow:0 10px 26px rgba(25,210,255,.3)}
.who b{display:block;font-size:17px}
.who span{font-size:13px;color:var(--dim)}
.badge{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;color:#95eebb;
  background:rgba(47,210,124,.1);border:1px solid rgba(47,210,124,.28);
  padding:6px 11px;border-radius:99px;margin-bottom:18px}
.dot{width:7px;height:7px;border-radius:99px;background:var(--ok);box-shadow:0 0 0 4px rgba(47,210,124,.18)}
dl{margin:0 0 20px;border-top:1px solid var(--line)}
dl div{display:flex;justify-content:space-between;gap:14px;padding:11px 2px;border-bottom:1px solid var(--line)}
dt{color:var(--dim);font-size:13px}
dd{margin:0;font-size:13.5px;text-align:right;word-break:break-all}
details{margin-top:4px;border:1px solid var(--line);border-radius:12px;padding:0 14px;background:rgba(255,255,255,.025)}
details[open]{padding-bottom:14px}
summary{cursor:pointer;padding:13px 0;font-size:13.5px;color:#b6a6ff;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"＋ ";opacity:.7}
details[open] summary::before{content:"－ "}
button.ghost{width:100%;margin-top:10px;padding:12px;border-radius:12px;cursor:pointer;font-size:14px;
  color:var(--txt);background:rgba(255,255,255,.05);border:1px solid var(--line);transition:background .15s}
button.ghost:hover{background:rgba(255,255,255,.1)}
.foot{margin:16px 4px 0;font-size:11.5px;color:#6a6a82;text-align:center;line-height:1.6}
@media(max-width:420px){.card{padding:22px 18px}h1{font-size:21px}}
`;

function layout({ title, body, showBrandSub = true }) {
  return `<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)} — ${esc(SITE_NAME)}</title>
<link rel="icon" href="data:,">
<style>${CSS}</style>
</head><body>
<div class="wrap">
  <div class="brand">
    <div class="logo">${esc(SITE_NAME.trim().charAt(0).toUpperCase() || 'D')}</div>
    <div><b>${esc(SITE_NAME)}</b>${showBrandSub ? '<span>защищённый доступ к аккаунту</span>' : ''}</div>
  </div>
  <div class="card">${body}</div>
  <p class="foot">Пароль хранится только как scrypt-хеш с индивидуальной солью.<br>Передача данных — по HTTPS. Демонстрационный стенд.</p>
</div>
<script>
document.querySelectorAll('[data-toggle]').forEach(function(btn){
  btn.addEventListener('click', function(){
    var inp = document.getElementById(btn.dataset.toggle);
    if(!inp) return;
    var show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    btn.textContent = show ? 'скрыть' : 'показать';
  });
});
var pw = document.getElementById('password'), meter = document.getElementById('meter');
if (pw && meter) {
  pw.addEventListener('input', function(){
    var v = pw.value, s = 0;
    if (v.length >= 8) s++;
    if (v.length >= 12) s++;
    if (/[a-zа-я]/.test(v) && /[A-ZА-Я]/.test(v)) s++;
    if (/[0-9]/.test(v)) s++;
    if (/[^A-Za-zА-Яа-я0-9\\s]/.test(v)) s++;
    var pct = [0, 22, 42, 62, 82, 100][s];
    var col = s <= 1 ? '#ff5f6d' : s <= 2 ? '#ffb020' : s <= 3 ? '#19d2ff' : '#2fd27c';
    meter.style.width = pct + '%';
    meter.style.background = col;
  });
}
</script>
</body></html>`;
}

const alert_ = (kind, text, code) =>
  text ? `<div class="msg ${kind}">${esc(text)}${code ? `<code>${esc(code)}</code>` : ''}</div>` : '';

const pwField = (id, name, label, placeholder = '••••••••', meter = false) => `
<div class="f">
  <label for="${id}">${esc(label)}</label>
  <div class="pw">
    <input id="${id}" name="${name}" type="password" placeholder="${esc(placeholder)}"
           autocomplete="new-password" required>
    <button type="button" data-toggle="${id}">показать</button>
  </div>
  ${meter ? '<div class="meter"><i id="meter"></i></div><div class="hint">Минимум 8 символов. Надёжнее — длинная фраза.</div>' : ''}
</div>`;

// ---------------------------------------------------------------------- страницы
function pageRegister({ csrf, err, values = {} }) {
  return layout({
    title: 'Регистрация',
    body: `
<h1>Создать аккаунт</h1>
<p class="sub">Укажите имя, почту и пароль. Пароль сохраняется только в виде хеша.</p>
${alert_('err', err)}
<form method="post" action="/register" novalidate>
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <div class="f">
    <label for="name">Имя</label>
    <input id="name" name="name" type="text" placeholder="Как вас зовут" value="${esc(values.name)}"
           autocomplete="name" maxlength="80" required>
  </div>
  <div class="f">
    <label for="email">Электронная почта</label>
    <input id="email" name="email" type="email" placeholder="you@example.com" value="${esc(values.email)}"
           autocomplete="email" maxlength="254" required>
  </div>
  ${pwField('password', 'password', 'Пароль', '••••••••', true)}
  ${pwField('password2', 'password2', 'Пароль ещё раз')}
  <button class="go" type="submit">Зарегистрироваться</button>
</form>
<p class="alt">Уже есть аккаунт? <a href="/login">Войти</a></p>`,
  });
}

function pageLogin({ csrf, err, ok, okCode, values = {} }) {
  return layout({
    title: 'Вход',
    body: `
<h1>Вход</h1>
<p class="sub">Введите почту и пароль, чтобы продолжить.</p>
${alert_('ok', ok, okCode)}
${alert_('err', err)}
<form method="post" action="/login" novalidate>
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <div class="f">
    <label for="email">Электронная почта</label>
    <input id="email" name="email" type="email" placeholder="you@example.com" value="${esc(values.email)}"
           autocomplete="email" required>
  </div>
  <div class="f">
    <div class="row">
      <label for="loginpw">Пароль</label>
      <a class="link" style="font-size:12.5px" href="/forgot">Забыли пароль?</a>
    </div>
    <div class="pw">
      <input id="loginpw" name="password" type="password" placeholder="••••••••" autocomplete="current-password" required>
      <button type="button" data-toggle="loginpw">показать</button>
    </div>
  </div>
  <button class="go" type="submit">Войти</button>
</form>
<p class="alt">Нет аккаунта? <a href="/register">Зарегистрироваться</a></p>`,
  });
}

function pageForgot({ csrf, err, ok, okCode, values = {} }) {
  return layout({
    title: 'Восстановление доступа',
    body: `
<h1>Восстановление доступа</h1>
<p class="sub">Укажите почту, на которую зарегистрирован аккаунт. Пришлём ссылку для смены пароля — она действует 30 минут.</p>
${alert_('ok', ok, okCode)}
${alert_('err', err)}
<form method="post" action="/forgot" novalidate>
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <div class="f">
    <label for="email">Электронная почта</label>
    <input id="email" name="email" type="email" placeholder="you@example.com" value="${esc(values.email)}"
           autocomplete="email" required>
  </div>
  <button class="go" type="submit">Отправить ссылку</button>
</form>
<p class="alt"><a href="/login">Вернуться ко входу</a></p>`,
  });
}

function pageReset({ csrf, token, err }) {
  return layout({
    title: 'Новый пароль',
    body: `
<h1>Новый пароль</h1>
<p class="sub">Придумайте новый пароль. После смены все активные входы будут завершены.</p>
${alert_('err', err)}
<form method="post" action="/reset" novalidate>
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <input type="hidden" name="token" value="${esc(token)}">
  ${pwField('password', 'password', 'Новый пароль', '••••••••', true)}
  ${pwField('password2', 'password2', 'Повторите пароль')}
  <button class="go" type="submit">Сохранить пароль</button>
</form>
<p class="alt"><a href="/login">Вернуться ко входу</a></p>`,
  });
}

function pageBadToken() {
  return layout({
    title: 'Ссылка недействительна',
    body: `
<h1>Ссылка недействительна</h1>
<p class="sub">Срок действия ссылки истёк (30 минут) или она уже была использована. Запросите восстановление заново.</p>
<form method="get" action="/forgot"><button class="go" type="submit">Запросить новую ссылку</button></form>
<p class="alt"><a href="/login">Вернуться ко входу</a></p>`,
  });
}

function pageHome({ user, csrf, err, ok, okCode }) {
  const initials = user.name.trim().split(/\s+/).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || 'U';
  const fmt = (ms) => new Date(ms).toLocaleString('ru-RU', { dateStyle: 'medium', timeStyle: 'short' });
  return layout({
    title: 'Вы вошли',
    showBrandSub: false,
    body: `
<div class="badge"><span class="dot"></span> Вы вошли</div>
<div class="who">
  <div class="ava">${esc(initials)}</div>
  <div><b>${esc(user.name)}</b><span>${esc(user.email)}</span></div>
</div>
${alert_('ok', ok, okCode)}
${alert_('err', err)}
<dl>
  <div><dt>Почта</dt><dd>${esc(user.email)}</dd></div>
  <div><dt>Регистрация</dt><dd>${esc(fmt(user.created_at))}</dd></div>
  <div><dt>Профиль изменён</dt><dd>${esc(fmt(user.updated_at))}</dd></div>
  <div><dt>Пароль</dt><dd>scrypt-хеш, соль индивидуальная</dd></div>
</dl>

<details>
  <summary>Сменить почту</summary>
  <form method="post" action="/change-email" novalidate>
    <input type="hidden" name="csrf" value="${esc(csrf)}">
    <div class="f">
      <label for="newemail">Новая почта</label>
      <input id="newemail" name="email" type="email" placeholder="new@example.com" required>
    </div>
    <div class="f">
      <label for="cpw">Текущий пароль</label>
      <div class="pw">
        <input id="cpw" name="password" type="password" placeholder="••••••••" autocomplete="current-password" required>
        <button type="button" data-toggle="cpw">показать</button>
      </div>
    </div>
    <button class="go" type="submit">Сохранить почту</button>
  </form>
</details>

<form method="post" action="/logout">
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <button class="ghost" type="submit">Выйти</button>
</form>`,
  });
}

// ----------------------------------------------------------------------- логика
function validateRegistration({ name, email, password, password2 }) {
  if (!name || name.trim().length < 2) return 'Укажите имя (минимум 2 символа).';
  if (name.length > 80) return 'Имя слишком длинное.';
  if (!EMAIL_RE.test(email) || email.length > 254) return 'Проверьте адрес почты — он выглядит некорректно.';
  if (!password || password.length < 8) return 'Пароль должен быть не короче 8 символов.';
  if (password.length > 200) return 'Пароль слишком длинный (максимум 200 символов).';
  if (password !== password2) return 'Пароли не совпадают.';
  return null;
}

function startSession(userId, extra = {}) {
  const token = randomToken();
  const now = Date.now();
  q.insertSession.run(sha256(token), userId, now, now + SESSION_TTL_MS);
  return { 'Set-Cookie': cookie('sid', token, SESSION_TTL_MS / 1000), ...extra };
}

const KNOWN_PATHS = ['/', '/register', '/login', '/logout', '/forgot', '/reset', '/change-email'];

async function handle(req, res, url) {
  const p = url.pathname.replace(/\/+$/, '') || '/';
  const user = currentUser(req);
  const sidSeed = parseCookies(req).sid || clientIp(req);
  const csrf = csrfFor(sidSeed);
  const ip = clientIp(req);

  if (req.method === 'GET' && p === '/healthz') {
    return send(res, 200, 'ok', { 'Content-Type': 'text/plain; charset=utf-8' });
  }

  // ------- POST: разбор формы и проверка CSRF
  let form = null;
  if (req.method === 'POST') {
    let raw;
    try { raw = await readBody(req); }
    catch { return send(res, 413, layout({ title: 'Ошибка', body: '<h1>Слишком большой запрос</h1>' })); }
    form = Object.fromEntries(new URLSearchParams(raw));
    if (!safeEqual(form.csrf || '', csrf)) {
      return send(res, 403, layout({
        title: 'Форма устарела',
        body: `<h1>Форма устарела</h1><p class="sub">Проверка безопасности не прошла — откройте страницу заново и повторите.</p>
               <form method="get" action="${p === '/register' ? '/register' : '/login'}"><button class="go">Обновить</button></form>`,
      }));
    }
  }

  // ------------------------------------------------------------------- главная
  if (p === '/' && req.method === 'GET') {
    if (!user) return redirect(res, '/login');
    return send(res, 200, pageHome({ user, csrf }));
  }

  // --------------------------------------------------------------- регистрация
  if (p === '/register') {
    if (user) return redirect(res, '/');
    if (req.method === 'GET') return send(res, 200, pageRegister({ csrf }));
    if (req.method === 'POST') {
      const rl = rateLimit(`reg:${ip}`, 10, 10 * 60 * 1000);
      if (!rl.ok) return send(res, 429, pageRegister({ csrf, err: `Слишком много попыток. Повторите через ${rl.retryAfter} с.` }));
      const name = String(form.name || '').trim();
      const email = normEmail(form.email);
      const values = { name, email };
      const err = validateRegistration({ name, email, password: form.password || '', password2: form.password2 || '' });
      if (err) return send(res, 400, pageRegister({ csrf, err, values }));
      if (q.userByEmail.get(email)) {
        return send(res, 409, pageRegister({ csrf, err: 'Этот адрес уже зарегистрирован. Попробуйте войти или восстановить пароль.', values }));
      }
      const now = Date.now();
      let info;
      try {
        info = q.insertUser.run(name, email, hashPassword(form.password), now, now);
      } catch (e) {
        log('ошибка регистрации:', e.message);
        return send(res, 409, pageRegister({ csrf, err: 'Этот адрес уже зарегистрирован.', values }));
      }
      log(`регистрация: id=${info.lastInsertRowid} email=${email}`);
      return redirect(res, '/', startSession(Number(info.lastInsertRowid)));
    }
  }

  // ---------------------------------------------------------------------- вход
  if (p === '/login') {
    if (user && req.method === 'GET') return redirect(res, '/');
    if (req.method === 'GET') {
      const ok = url.searchParams.get('reset') === '1' ? 'Пароль изменён. Войдите с новым паролем.' : '';
      return send(res, 200, pageLogin({ csrf, ok }));
    }
    if (req.method === 'POST') {
      const email = normEmail(form.email);
      const rl = rateLimit(`login:${ip}:${email}`, 8, 15 * 60 * 1000);
      if (!rl.ok) {
        return send(res, 429, pageLogin({ csrf, err: `Слишком много попыток входа. Повторите через ${rl.retryAfter} с.`, values: { email } }));
      }
      const row = q.userByEmail.get(email);
      const pw = String(form.password || '');
      // Одинаковый текст ошибки и сопоставимое время для «нет пользователя» и «неверный пароль».
      let okPass = false;
      if (row) okPass = verifyPassword(pw, row.pass_hash);
      else verifyPassword(pw, hashPassword('timing-equalizer'));
      if (!okPass) {
        log(`неудачный вход: email=${email} ip=${ip}`);
        return send(res, 401, pageLogin({ csrf, err: 'Неверная почта или пароль.', values: { email } }));
      }
      log(`вход: id=${row.id} email=${email}`);
      return redirect(res, '/', startSession(row.id));
    }
  }

  // --------------------------------------------------------------------- выход
  if (p === '/logout' && req.method === 'POST') {
    const token = parseCookies(req).sid;
    if (token) q.deleteSession.run(sha256(token));
    return redirect(res, '/login', { 'Set-Cookie': cookie('sid', '', 0) });
  }

  // ------------------------------------------------------ восстановление: заявка
  if (p === '/forgot') {
    if (req.method === 'GET') return send(res, 200, pageForgot({ csrf }));
    if (req.method === 'POST') {
      const email = normEmail(form.email);
      const rl = rateLimit(`forgot:${ip}`, 5, 15 * 60 * 1000);
      if (!rl.ok) return send(res, 429, pageForgot({ csrf, err: `Слишком много запросов. Повторите через ${rl.retryAfter} с.`, values: { email } }));

      const row = EMAIL_RE.test(email) ? q.userByEmail.get(email) : null;
      let devLink = '';
      if (row) {
        const token = randomToken();
        const now = Date.now();
        q.invalidateResets.run(now, row.id);           // прежние ссылки аннулируем
        q.insertReset.run(sha256(token), row.id, now, now + RESET_TTL_MS);
        const link = `${PUBLIC_URL}/reset?token=${token}`;
        const delivered = await sendMail({
          to: email,
          subject: `${SITE_NAME}: восстановление доступа`,
          text: `Здравствуйте, ${row.name}!\n\nВы запросили смену пароля. Перейдите по ссылке (действует 30 минут):\n${link}\n\nЕсли это были не вы — просто проигнорируйте письмо, пароль останется прежним.\n`,
        });
        if (!delivered && SHOW_RESET_LINK) devLink = link;
        log(`заявка на восстановление: id=${row.id} доставлено=${delivered}`);
      } else {
        log(`заявка на восстановление для неизвестного адреса: ${email}`);
      }
      // Ответ одинаковый независимо от того, зарегистрирован ли адрес.
      return send(res, 200, pageForgot({
        csrf,
        ok: devLink
          ? 'Ссылка создана. Почта на этом стенде пока не отправляется, поэтому ссылка показана здесь (действует 30 минут):'
          : 'Если такой адрес зарегистрирован, мы отправили на него ссылку для смены пароля. Проверьте почту.',
        okCode: devLink,
      }));
    }
  }

  // ------------------------------------------------- восстановление: новый пароль
  if (p === '/reset') {
    const token = req.method === 'GET' ? (url.searchParams.get('token') || '') : String(form.token || '');
    const row = token ? q.resetByHash.get(sha256(token)) : null;
    const valid = row && !row.used_at && row.expires_at > Date.now();
    if (!valid) return send(res, 400, pageBadToken());
    if (req.method === 'GET') return send(res, 200, pageReset({ csrf, token }));
    if (req.method === 'POST') {
      const pw = String(form.password || '');
      const pw2 = String(form.password2 || '');
      let err = null;
      if (pw.length < 8) err = 'Пароль должен быть не короче 8 символов.';
      else if (pw.length > 200) err = 'Пароль слишком длинный (максимум 200 символов).';
      else if (pw !== pw2) err = 'Пароли не совпадают.';
      if (err) return send(res, 400, pageReset({ csrf, token, err }));
      const now = Date.now();
      q.updatePass.run(hashPassword(pw), now, row.user_id);
      q.useReset.run(now, row.token_hash);
      q.deleteUserSessions.run(row.user_id);          // все прежние входы завершаем
      log(`пароль изменён по ссылке восстановления: id=${row.user_id}`);
      return redirect(res, '/login?reset=1', { 'Set-Cookie': cookie('sid', '', 0) });
    }
  }

  // ------------------------------------------------------------- смена почты
  if (p === '/change-email' && req.method === 'POST') {
    if (!user) return redirect(res, '/login');
    const email = normEmail(form.email);
    const rl = rateLimit(`chemail:${user.id}`, 6, 15 * 60 * 1000);
    if (!rl.ok) return send(res, 429, pageHome({ user, csrf, err: `Слишком много попыток. Повторите через ${rl.retryAfter} с.` }));
    if (!EMAIL_RE.test(email) || email.length > 254) {
      return send(res, 400, pageHome({ user, csrf, err: 'Проверьте новый адрес почты.' }));
    }
    if (!verifyPassword(String(form.password || ''), user.pass_hash)) {
      return send(res, 401, pageHome({ user, csrf, err: 'Неверный текущий пароль.' }));
    }
    if (email === user.email) return send(res, 400, pageHome({ user, csrf, err: 'Это уже ваш текущий адрес.' }));
    if (q.userByEmail.get(email)) return send(res, 409, pageHome({ user, csrf, err: 'Этот адрес уже занят другим аккаунтом.' }));
    q.updateEmail.run(email, Date.now(), user.id);
    log(`смена почты: id=${user.id}`);
    const fresh = q.userById.get(user.id);
    return send(res, 200, pageHome({ user: fresh, csrf, ok: 'Адрес почты обновлён.' }));
  }

  // ------------------------------------------------------------------- 404/405
  if (KNOWN_PATHS.includes(p)) {
    return send(res, 405, layout({ title: 'Метод не поддерживается', body: '<h1>Метод не поддерживается</h1>' }));
  }
  return send(res, 404, layout({
    title: 'Страница не найдена',
    body: `<h1>404</h1><p class="sub">Такой страницы нет.</p>
           <form method="get" action="/"><button class="go">На главную</button></form>`,
  }));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  handle(req, res, url).catch((e) => {
    log('необработанная ошибка:', e?.stack || e?.message || e);
    if (!res.headersSent) {
      send(res, 500, layout({ title: 'Ошибка', body: '<h1>Внутренняя ошибка</h1><p class="sub">Попробуйте повторить позже.</p>' }));
    } else res.end();
  });
});

server.headersTimeout = 20000;
server.requestTimeout = 30000;
server.listen(PORT, HOST, () => {
  log(`stub-auth слушает http://${HOST}:${PORT}  (публично: ${PUBLIC_URL})`);
  log(`БД: ${DB_PATH}; SMTP: ${SMTP.host ? SMTP.host + ':' + SMTP.port : 'не настроен (ссылки пишутся в ' + MAIL_LOG + ')'}`);
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    log(`${sig}, завершаюсь`);
    server.close(() => { try { db.close(); } catch {} process.exit(0); });
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
