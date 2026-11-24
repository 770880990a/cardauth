'use strict';
/**
 * 卡密验证系统 —— 本地一体化服务
 * 无需外网服务器：双击即运行，数据存本地 SQLite
 * 默认端口 8787，可改环境变量 PORT
 */
const path = require('path');
const fs = require('fs');
const os = require('os');
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const { db, now, hashPassword, getSetting, setSetting, DB_PATH } = require('./db');
const C = require('./core');

const app = express();
const PORT = parseInt(process.env.PORT || '8787', 10);
// 默认监听所有网卡，这样手机/其他电脑能通过局域网 IP 访问
const HOST = process.env.HOST || '0.0.0.0';

app.disable('x-powered-by');
// 云端（有反向代理）才信任代理头，本地运行时不需要，否则会触发限流绕过告警
const IS_CLOUD = !!(process.env.RENDER || process.env.RAILWAY_ENVIRONMENT ||
  process.env.KOYEB_APP_NAME || process.env.FLY_APP_NAME ||
  process.env.TRUST_PROXY === '1');
if (IS_CLOUD) app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.text({ type: 'text/plain', limit: '2mb' }));

/* ---------------- 工具 ---------------- */
const clientIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.socket.remoteAddress || '';

function safe(fn) {
  return async (req, res) => {
    try { await fn(req, res); }
    catch (e) {
      console.error('[error]', e);
      res.json({ code: C.CODE.SERVER_ERROR, msg: '服务端异常: ' + e.message });
    }
  };
}

function authAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || req.query.token;
  try {
    const p = jwt.verify(token, getSetting('jwt_secret'));
    if (p.role !== 'admin') throw new Error('role');
    req.admin = p;
    next();
  } catch (e) {
    res.status(401).json({ code: 401, msg: '登录已失效，请重新登录' });
  }
}

function authAgent(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || req.query.token;
  try {
    const p = jwt.verify(token, getSetting('jwt_secret'));
    if (p.role !== 'agent') throw new Error('role');
    const a = db.prepare('SELECT * FROM agents WHERE id=?').get(p.id);
    if (!a) throw new Error('nf');
    if (a.frozen) return res.status(403).json({ code: C.CODE.AGENT_FROZEN, msg: '账号已冻结' });
    req.agent = a;
    next();
  } catch (e) {
    res.status(401).json({ code: 401, msg: '登录已失效，请重新登录' });
  }
}

const ok = (res, data = {}, msg = 'ok') => res.json({ code: 0, msg, ...data });
const fail = (res, code, msg) => res.json({ code, msg });

/* =====================================================================
 *  一、客户端对接接口 /api/client/*
 *  所有请求需带 sign / timestamp / nonce（可在系统设置里关闭）
 * ===================================================================== */
const clientLimiter = rateLimit({
  windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false,
  message: { code: 9003, msg: '请求过于频繁，请稍后再试' },
});

/** 把请求体统一成参与签名的规范字符串
 *  规则：取「业务字段」= 请求体去掉 sign/timestamp/nonce/card_key/device_id 后的部分，
 *  按 key 升序、紧凑 JSON。card_key 与 device_id 已在 payload 前段单独参与签名。
 */
function normBody(req) {
  const p = { ...(req.body || {}) };
  delete p.sign; delete p.timestamp; delete p.nonce;
  delete p.card_key; delete p.device_id;
  const keys = Object.keys(p).sort();
  const o = {};
  for (const k of keys) o[k] = p[k];
  return JSON.stringify(o);
}

function guardSign(req, res, next) {
  if (getSetting('sign_required', '1') === '0') return next();
  const p = req.body || {};
  const r = C.checkSign(p, normBody(req));
  if (!r.ok) {
    C.logVerify({ cardKey: p.card_key, deviceId: p.device_id, ip: clientIp(req),
      action: 'sign', ok: false, code: r.code, msg: r.msg });
    return res.json({ code: r.code, msg: r.msg });
  }
  next();
}

/** 1. 激活卡密 */
app.post('/api/client/activate', clientLimiter, guardSign, safe((req, res) => {
  const { card_key, device_id } = req.body;
  const r = C.activateCard({ cardKey: card_key, deviceId: device_id, ip: clientIp(req) });
  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'activate', ok: r.ok, code: r.code, msg: r.msg });
  if (!r.ok) return res.json({ code: r.code, msg: r.msg, card: r.card || null });
  res.json({ code: 0, msg: r.msg, card: r.card, already: !!r.already });
}));

/** 2. 验证登录（每次启动客户端调用） */
app.post('/api/client/verify', clientLimiter, guardSign, safe((req, res) => {
  const { card_key, device_id } = req.body;
  const r = C.verifyCard({ cardKey: card_key, deviceId: device_id, ip: clientIp(req) });
  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'verify', ok: r.ok, code: r.code, msg: r.msg });
  if (!r.ok) return res.json({ code: r.code, msg: r.msg, card: r.card || null });
  res.json({ code: 0, msg: r.msg, card: r.card });
}));

/** 3. 心跳（建议 5 分钟一次，掉线即踢） */
app.post('/api/client/heartbeat', clientLimiter, guardSign, safe((req, res) => {
  const { card_key, device_id } = req.body;
  const r = C.verifyCard({ cardKey: card_key, deviceId: device_id, ip: clientIp(req) });
  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'heartbeat', ok: r.ok, code: r.code, msg: r.msg });
  if (!r.ok) return res.json({ code: r.code, msg: r.msg, card: r.card || null });
  res.json({ code: 0, msg: 'ok', card: r.card });
}));

/** 4. 卡密充值额度（兑换额度卡 / 叠加） */
app.post('/api/client/redeem', clientLimiter, guardSign, safe((req, res) => {
  const { card_key, redeem_key, device_id } = req.body;
  // 先校验当前登录卡
  const r0 = C.verifyCard({ cardKey: card_key, deviceId: device_id, ip: clientIp(req) });
  if (!r0.ok) return res.json({ code: r0.code, msg: r0.msg });

  // 再激活充值卡（把额度加到自己账户上）
  const target = db.prepare('SELECT * FROM cards WHERE card_key=?').get(String(redeem_key || '').trim().toUpperCase());
  if (!target) return res.json({ code: C.CODE.CARD_NOT_FOUND, msg: '充值卡号不存在' });
  if (target.unit === 'day') return res.json({ code: 1005, msg: '该卡为时长卡，请使用"激活"接口' });
  if (target.status !== 'unused') return res.json({ code: C.CODE.CARD_USED, msg: '充值卡已被使用' });
  if (target.status === 'disabled') return res.json({ code: C.CODE.CARD_DISABLED, msg: '充值卡已封禁' });

  const cur = C.checkCard(card_key);
  if (!cur.ok) return res.json({ code: cur.code, msg: cur.msg });

  let amount = target.value;

  const t = now();
  let balance = 0;

  const tx = db.transaction(() => {
    db.prepare(`UPDATE cards SET status='used', activated_at=?, used_count=used_count+1 WHERE id=?`)
      .run(t, target.id);
    const res2 = C.changeCredit(cur.card.card_key, amount, 'card_redeem', target.card_key,
      `充值卡 ${target.type_name}`, clientIp(req));
    if (!res2.ok) throw new Error(res2.msg);
    balance = res2.balance;
  });

  try { tx(); }
  catch (e) { return res.json({ code: C.CODE.SERVER_ERROR, msg: e.message }); }

  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'redeem', ok: true, code: 0, msg: `充值 +${amount}` });
  res.json({ code: 0, msg: `充值成功 +${amount}`, add: amount, balance });
}));

/** 5. 消耗额度 */
app.post('/api/client/consume', clientLimiter, guardSign, safe((req, res) => {
  const { card_key, device_id, amount, remark } = req.body;
  const r = C.consumeCredit({ cardKey: card_key, amount, deviceId: device_id, ip: clientIp(req), remark });
  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'consume', ok: r.ok, code: r.code, msg: r.msg });
  if (!r.ok) return res.json({ code: r.code, msg: r.msg });
  res.json({ code: 0, msg: r.msg, balance: r.balance, cost: r.cost });
}));

/** 6. 查询账户信息 */
app.post('/api/client/info', clientLimiter, guardSign, safe((req, res) => {
  const { card_key, device_id } = req.body;
  const cur = C.checkCard(card_key);
  if (!cur.ok) return res.json({ code: cur.code, msg: cur.msg });
  const u = C.ensureUser(cur.card.card_key);
  res.json({ code: 0, msg: 'ok', card: C.publicCard(cur.card, u) });
}));

/** 7. 公告/版本（不需要签名，方便客户端拉更新） */
app.get('/api/client/notice', safe((req, res) => {
  const appId = String(req.query.app_id || 'default');
  const app = db.prepare('SELECT * FROM apps WHERE app_id=? AND enabled=1').get(appId);
  const rows = db.prepare('SELECT * FROM notices WHERE enabled=1 ORDER BY id DESC LIMIT 20').all();
  const latest = rows[0] || null;
  res.json({
    code: 0, msg: 'ok',
    version: (app && app.version) || (latest ? latest.ver : getSetting('client_ver', '1.0.0')),
    force_update: latest ? !!latest.force : false,
    download_url: (app && app.download_url) || getSetting('download_url', ''),
    notice: app ? app.notice : '',
    notices: rows,
  });
}));

/** 8. 服务端时间（客户端校准用） */
app.get('/api/client/time', (req, res) => res.json({ code: 0, time: now(), ts: Math.floor(now() / 1000) }));

/** 9. 配置下发（客户端启动时拉取；带 app_id 则下发该应用的配置） */
app.get('/api/client/config', safe((req, res) => {
  const appId = String(req.query.app_id || 'default');
  const app = db.prepare('SELECT * FROM apps WHERE app_id=? AND enabled=1').get(appId);
  if (!app) return res.json({ code: C.CODE.APP_NOT_FOUND, msg: '应用不存在或已停用' });

  res.json({
    code: 0,
    app_id: app.app_id,
    app_name: app.name,
    site_name: getSetting('site_name', '卡密验证系统'),
    bind_device: getSetting('bind_device', '1') === '1',
    sign_required: getSetting('sign_required', '1') === '1',
    heart_interval: parseInt(getSetting('heart_interval', '300'), 10),
    client_ver: app.version || '1.0.0',
    download_url: app.download_url || '',
    notice: app.notice || '',
    // 卡类型按「时长卡 / 额度卡 / 次数卡」分组返回，客户端可按需展示
    types: db.prepare(`SELECT code,name,unit,value FROM card_types
      WHERE app_id=? AND enabled=1 ORDER BY unit, sort`).all(appId),
  });
}));

/* =====================================================================
 *  二、管理后台接口 /api/admin/*
 * ===================================================================== */
const loginLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, message: { code: 429, msg: '登录尝试过多，请10分钟后再试' } });

app.post('/api/admin/login', loginLimiter, safe((req, res) => {
  const { username, password } = req.body || {};
  const a = db.prepare('SELECT * FROM admins WHERE username=?').get(username || '');
  if (!a) return fail(res, 401, '用户名或密码错误');
  if (hashPassword(password || '', a.salt) !== a.password_hash) return fail(res, 401, '用户名或密码错误');
  db.prepare('UPDATE admins SET last_login=? WHERE id=?').run(now(), a.id);
  const token = jwt.sign({ id: a.id, role: 'admin', username: a.username }, getSetting('jwt_secret'), { expiresIn: '12h' });
  ok(res, { token, username: a.username });
}));

app.get('/api/admin/me', authAdmin, (req, res) => ok(res, { admin: req.admin }));

app.post('/api/admin/password', authAdmin, safe((req, res) => {
  const { old_pwd, new_pwd } = req.body || {};
  const a = db.prepare('SELECT * FROM admins WHERE id=?').get(req.admin.id);
  if (hashPassword(old_pwd || '', a.salt) !== a.password_hash) return fail(res, 401, '原密码错误');
  if (!new_pwd || String(new_pwd).length < 6) return fail(res, 400, '新密码至少6位');
  const salt = require('crypto').randomBytes(8).toString('hex');
  db.prepare('UPDATE admins SET password_hash=?, salt=? WHERE id=?')
    .run(hashPassword(new_pwd, salt), salt, a.id);
  ok(res, {}, '密码已修改');
}));

/* ---- 概览统计 ---- */
app.get('/api/admin/stats', authAdmin, safe((req, res) => {
  const q = (s, ...a) => db.prepare(s).get(...a);
  const t = now();
  const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
  const data = {
    cards_total: q('SELECT COUNT(*) c FROM cards').c,
    cards_unused: q("SELECT COUNT(*) c FROM cards WHERE status='unused'").c,
    cards_used: q("SELECT COUNT(*) c FROM cards WHERE status='used'").c,
    cards_expired: q("SELECT COUNT(*) c FROM cards WHERE status='expired'").c,
    cards_disabled: q("SELECT COUNT(*) c FROM cards WHERE status='disabled'").c,
    agents_total: q('SELECT COUNT(*) c FROM agents').c,
    agents_frozen: q('SELECT COUNT(*) c FROM agents WHERE frozen=1').c,
    verify_today: q('SELECT COUNT(*) c FROM verify_logs WHERE created_at>=?', todayStart.getTime()).c,
    verify_fail_today: q('SELECT COUNT(*) c FROM verify_logs WHERE ok=0 AND created_at>=?', todayStart.getTime()).c,
    credit_total: q('SELECT IFNULL(SUM(total_credit),0) s FROM users').s,
    credit_used: q('SELECT IFNULL(SUM(used_credit),0) s FROM users').s,
    users_total: q('SELECT COUNT(*) c FROM users').c,
    vip_active: q('SELECT COUNT(*) c FROM users WHERE expire_at>?', t).c,
    withdraw_pending: q("SELECT IFNULL(SUM(amount),0) s FROM withdrawals WHERE status='pending'").s,
    agent_balance_total: +(q('SELECT IFNULL(SUM(balance),0) s FROM agents').s).toFixed(2),
    server_time: new Date().toLocaleString('zh-CN'),
    uptime_min: Math.floor(process.uptime() / 60),
  };
  // 近7天验证趋势
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const s = new Date(); s.setHours(0, 0, 0, 0); s.setDate(s.getDate() - i);
    const e = s.getTime() + 86400000;
    days.push({
      date: `${s.getMonth() + 1}/${s.getDate()}`,
      total: q('SELECT COUNT(*) c FROM verify_logs WHERE created_at>=? AND created_at<?', s.getTime(), e).c,
      fail: q('SELECT COUNT(*) c FROM verify_logs WHERE ok=0 AND created_at>=? AND created_at<?', s.getTime(), e).c,
    });
  }
  data.trend = days;
  ok(res, data);
}));

/* ---- 卡类型（按应用隔离，分时长卡 / 额度卡 / 次数卡） ---- */
app.get('/api/admin/types', authAdmin, safe((req, res) => {
  const { app_id = '', unit = '' } = req.query;
  const w = []; const a = [];
  if (app_id) { w.push('app_id=?'); a.push(app_id); }
  if (unit) { w.push('unit=?'); a.push(unit); }
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  ok(res, { list: db.prepare(`SELECT * FROM card_types ${where} ORDER BY unit, sort, id`).all(...a) });
}));

app.post('/api/admin/types', authAdmin, safe((req, res) => {
  const { code, name, unit, value, enabled, sort, remark, app_id } = req.body || {};
  const appId = app_id || 'default';
  if (!code || !name) return fail(res, 400, 'code 和 name 必填');
  if (!['hour', 'day', 'credit'].includes(unit)) return fail(res, 400, 'unit 只能是 hour/day/credit');
  // 新建时未指定 enabled 一律视为启用
  const en = (enabled === undefined || enabled === null) ? 1 : (enabled ? 1 : 0);
  try {
    db.prepare(`INSERT INTO card_types(app_id,code,name,unit,value,enabled,sort,remark,created_at)
      VALUES(?,?,?,?,?,?,?,?,?)`)
      .run(appId, code, name, unit, parseInt(value, 10) || 0,
        en, parseInt(sort, 10) || 100, remark || '', now());
    ok(res, {}, '添加成功');
  } catch (e) { fail(res, 400, '该应用下类型代码已存在'); }
}));

app.put('/api/admin/types/:id', authAdmin, safe((req, res) => {
  const { name, unit, value, enabled, sort, remark } = req.body || {};
  // 前端编辑时会明确传 0/1；未传则保持原值不变
  let en = enabled;
  if (en === undefined || en === null) {
    const cur = db.prepare('SELECT enabled FROM card_types WHERE id=?').get(req.params.id);
    en = cur ? cur.enabled : 1;
  }
  db.prepare(`UPDATE card_types SET name=?,unit=?,value=?,enabled=?,sort=?,remark=? WHERE id=?`)
    .run(name, unit, parseInt(value, 10) || 0,
      en ? 1 : 0, parseInt(sort, 10) || 100, remark || '', req.params.id);
  ok(res, {}, '已更新');
}));

app.delete('/api/admin/types/:id', authAdmin, safe((req, res) => {
  db.prepare('DELETE FROM card_types WHERE id=?').run(req.params.id);
  ok(res, {}, '已删除');
}));

/* ============================================================
 *  应用管理（多应用：一个后台管多个软件，各自独立卡密池与密钥）
 * ============================================================ */
app.get('/api/admin/apps', authAdmin, safe((req, res) => {
  const list = db.prepare(`
    SELECT a.*,
      (SELECT COUNT(*) FROM cards c WHERE c.app_id=a.app_id) card_total,
      (SELECT COUNT(*) FROM cards c WHERE c.app_id=a.app_id AND c.status='unused') card_unused,
      (SELECT COUNT(*) FROM card_types t WHERE t.app_id=a.app_id) type_total
    FROM apps a ORDER BY a.id`).all();
  ok(res, { list });
}));

app.post('/api/admin/apps', authAdmin, safe((req, res) => {
  const { app_id, name, version, download_url, notice, remark } = req.body || {};
  const id = String(app_id || '').trim();
  if (!id) return fail(res, 400, '应用标识必填');
  if (!/^[a-zA-Z0-9_-]{2,32}$/.test(id)) return fail(res, 400, '应用标识只能是2-32位字母数字下划线中划线');
  if (!name) return fail(res, 400, '应用名称必填');
  const exists = db.prepare('SELECT 1 FROM apps WHERE app_id=?').get(id);
  if (exists) return fail(res, 400, '应用标识已存在');
  const secret = require('crypto').randomBytes(24).toString('hex');
  db.prepare(`INSERT INTO apps(app_id,name,secret,version,download_url,notice,enabled,remark,created_at)
    VALUES(?,?,?,?,?,?,1,?,?)`)
    .run(id, name, secret, version || '1.0.0', download_url || '', notice || '', remark || '', now());
  ok(res, { app_id: id, secret }, '应用创建成功');
}));

app.put('/api/admin/apps/:appId', authAdmin, safe((req, res) => {
  const { name, version, download_url, notice, enabled, remark } = req.body || {};
  db.prepare(`UPDATE apps SET name=?,version=?,download_url=?,notice=?,enabled=?,remark=? WHERE app_id=?`)
    .run(name, version || '1.0.0', download_url || '', notice || '',
      enabled ? 1 : 0, remark || '', req.params.appId);
  ok(res, {}, '已更新');
}));

app.post('/api/admin/apps/:appId/secret', authAdmin, safe((req, res) => {
  const s = require('crypto').randomBytes(24).toString('hex');
  db.prepare('UPDATE apps SET secret=? WHERE app_id=?').run(s, req.params.appId);
  ok(res, { secret: s }, '密钥已重置，请同步更新客户端');
}));

app.delete('/api/admin/apps/:appId', authAdmin, safe((req, res) => {
  const appId = req.params.appId;
  if (appId === 'default') return fail(res, 400, '默认应用不允许删除');
  const n = db.prepare('SELECT COUNT(*) c FROM cards WHERE app_id=?').get(appId).c;
  if (n > 0) return fail(res, 400, `该应用下还有 ${n} 张卡密，请先删除或转移卡密`);
  db.prepare('DELETE FROM card_types WHERE app_id=?').run(appId);
  db.prepare('DELETE FROM apps WHERE app_id=?').run(appId);
  ok(res, {}, '已删除');
}));

/* ---- 卡密管理 ---- */
app.get('/api/admin/cards', authAdmin, safe((req, res) => {
  const { page = 1, size = 20, kw = '', status = '', type = '', agent = '', batch = '',
          app_id = '', unit = '', exclude_unit = '' } = req.query;
  const lim = Math.min(500, parseInt(size, 10) || 20);
  const off = (Math.max(1, parseInt(page, 10) || 1) - 1) * lim;
  const w = []; const a = [];
  if (kw) { w.push('(c.card_key LIKE ? OR c.owner_device LIKE ? OR c.remark LIKE ?)'); a.push(`%${kw}%`, `%${kw}%`, `%${kw}%`); }
  if (status) { w.push('c.status=?'); a.push(status); }
  if (type) { w.push('c.type_code=?'); a.push(type); }
  if (agent) { w.push('c.agent_id=?'); a.push(agent); }
  if (batch) { w.push('c.batch_no=?'); a.push(batch); }
  if (app_id) { w.push('c.app_id=?'); a.push(app_id); }
  if (unit) { w.push('c.unit=?'); a.push(unit); }
  // 排除某个大类（卡密管理页用 exclude_unit=credit 排除额度卡）
  if (exclude_unit) { w.push('c.unit<>?'); a.push(exclude_unit); }
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) c FROM cards c ${where}`).get(...a).c;
  const list = db.prepare(`SELECT c.*, g.username agent_name, ap.name app_name FROM cards c
    LEFT JOIN agents g ON g.id=c.agent_id
    LEFT JOIN apps ap ON ap.app_id=c.app_id
    ${where} ORDER BY c.id DESC LIMIT ? OFFSET ?`)
    .all(...a, lim, off);
  ok(res, { total, page: parseInt(page, 10), size: lim, list });
}));

app.post('/api/admin/cards/generate', authAdmin, safe((req, res) => {
  const { type_code, count, max_devices, remark, prefix, app_id, type_value } = req.body || {};
  if (prefix) setSetting('card_prefix', prefix);
  const r = C.generateCards({
    typeCode: type_code, count, agentId: null,
    maxDevices: parseInt(max_devices, 10) || 1, remark: remark || '',
    appId: app_id || 'default',
    typeValue: type_value,   // 额度卡/次数卡的手动面值
  });
  if (!r.ok) return fail(res, r.code, r.msg);
  const unitText = r.unit === 'hour' ? `${r.face_value} 小时`
    : r.unit === 'day' ? `${r.face_value} 天`
    : `${r.face_value} 额度`;
  ok(res, r, `成功生成 ${r.count} 张（每张 ${unitText}）`);
}));

app.post('/api/admin/cards/:id/disable', authAdmin, safe((req, res) => {
  const c = db.prepare('SELECT * FROM cards WHERE id=?').get(req.params.id);
  if (!c) return fail(res, 404, '卡密不存在');
  db.prepare('UPDATE cards SET status=? WHERE id=?').run(c.status === 'disabled' ? 'unused' : 'disabled', c.id);
  ok(res, {}, c.status === 'disabled' ? '已解封' : '已封禁');
}));

app.post('/api/admin/cards/:id/unbind', authAdmin, safe((req, res) => {
  db.prepare('DELETE FROM card_devices WHERE card_id=?').run(req.params.id);
  db.prepare('UPDATE cards SET owner_device=NULL WHERE id=?').run(req.params.id);
  ok(res, {}, '设备已解绑');
}));

app.post('/api/admin/cards/:id/reset', authAdmin, safe((req, res) => {
  db.prepare(`UPDATE cards SET status='unused', activated_at=NULL, expire_at=NULL, used_count=0,
    owner_device=NULL, remain=value WHERE id=?`).run(req.params.id);
  db.prepare('DELETE FROM card_devices WHERE card_id=?').run(req.params.id);
  ok(res, {}, '卡密已重置为未使用');
}));

app.post('/api/admin/cards/:id/extend', authAdmin, safe((req, res) => {
  const days = parseInt(req.body.days, 10) || 0;
  const c = db.prepare('SELECT * FROM cards WHERE id=?').get(req.params.id);
  if (!c) return fail(res, 404, '卡密不存在');
  const add = days * 86400000;
  const base = Math.max(now(), c.expire_at || 0);
  db.prepare('UPDATE cards SET expire_at=? WHERE id=?').run(base + add, c.id);
  db.prepare('UPDATE users SET expire_at=? WHERE card_key=?').run(base + add, c.card_key);
  ok(res, {}, `已延长 ${days} 天`);
}));

app.delete('/api/admin/cards/:id', authAdmin, safe((req, res) => {
  db.prepare('DELETE FROM cards WHERE id=?').run(req.params.id);
  ok(res, {}, '已删除');
}));

app.post('/api/admin/cards/disable-batch', authAdmin, safe((req, res) => {
  const { batch_no } = req.body || {};
  const r = db.prepare("UPDATE cards SET status='disabled' WHERE batch_no=?").run(batch_no);
  ok(res, { affected: r.changes }, `已封禁 ${r.changes} 张`);
}));

/** 导出卡密（返回纯文本，前端生成 txt/csv 下载） */
app.get('/api/admin/cards/export', authAdmin, safe((req, res) => {
  const { batch = '', status = '', type = '' } = req.query;
  const w = []; const a = [];
  if (batch) { w.push('batch_no=?'); a.push(batch); }
  if (status) { w.push('status=?'); a.push(status); }
  if (type) { w.push('type_code=?'); a.push(type); }
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const rows = db.prepare(`SELECT card_key,type_name,value,unit,status,created_at FROM cards ${where} ORDER BY id`).all(...a);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(rows.map(r => r.card_key).join('\r\n'));
}));

/* ---- 用户/额度 ---- */
app.get('/api/admin/users', authAdmin, safe((req, res) => {
  const { page = 1, size = 20, kw = '' } = req.query;
  const lim = Math.min(500, parseInt(size, 10) || 20);
  const off = (Math.max(1, parseInt(page, 10) || 1) - 1) * lim;
  const w = kw ? 'WHERE card_key LIKE ?' : '';
  const a = kw ? [`%${kw}%`] : [];
  const total = db.prepare(`SELECT COUNT(*) c FROM users ${w}`).get(...a).c;
  const list = db.prepare(`SELECT * FROM users ${w} ORDER BY updated_at DESC LIMIT ? OFFSET ?`)
    .all(...a, lim, off).map(u => ({
      ...u,
      expire_at_text: u.expire_at ? new Date(u.expire_at).toLocaleString('zh-CN') : '-',
      is_vip: !!(u.expire_at && u.expire_at > now()),
    }));
  ok(res, { total, page: parseInt(page, 10), size: lim, list });
}));

app.post('/api/admin/users/credit', authAdmin, safe((req, res) => {
  const { card_key, delta, remark } = req.body || {};
  const d = parseInt(delta, 10);
  if (!card_key || !d) return fail(res, 400, '参数错误');
  const r = C.changeCredit(card_key.trim().toUpperCase(), d, 'admin_adjust', '',
    remark || (d > 0 ? '管理员充值' : '管理员扣除'), 'admin');
  if (!r.ok) return fail(res, r.code, r.msg);
  ok(res, { balance: r.balance }, `操作成功，当前额度 ${r.balance}`);
}));

app.post('/api/admin/users/ban', authAdmin, safe((req, res) => {
  const { card_key, ban } = req.body || {};
  db.prepare('UPDATE users SET ban=?, updated_at=? WHERE card_key=?')
    .run(ban ? 1 : 0, now(), String(card_key).trim().toUpperCase());
  ok(res, {}, ban ? '已封禁' : '已解封');
}));

app.get('/api/admin/credits-log', authAdmin, safe((req, res) => {
  const { page = 1, size = 30, kw = '' } = req.query;
  const lim = Math.min(500, parseInt(size, 10) || 30);
  const off = (Math.max(1, parseInt(page, 10) || 1) - 1) * lim;
  const w = kw ? 'WHERE card_key LIKE ?' : '';
  const a = kw ? [`%${kw}%`] : [];
  const total = db.prepare(`SELECT COUNT(*) c FROM credits_log ${w}`).get(...a).c;
  const list = db.prepare(`SELECT * FROM credits_log ${w} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...a, lim, off);
  ok(res, { total, list });
}));

/* ---- 代理商 ---- */
app.get('/api/admin/agents', authAdmin, safe((req, res) => {
  const { page = 1, size = 20, kw = '' } = req.query;
  const lim = Math.min(500, parseInt(size, 10) || 20);
  const off = (Math.max(1, parseInt(page, 10) || 1) - 1) * lim;
  const w = kw ? 'WHERE a.username LIKE ? OR a.nickname LIKE ? OR a.contact LIKE ?' : '';
  const a = kw ? [`%${kw}%`, `%${kw}%`, `%${kw}%`] : [];
  const total = db.prepare(`SELECT COUNT(*) c FROM agents a ${w}`).get(...a).c;
  const list = db.prepare(`SELECT a.*, p.username parent_name,
      (SELECT COUNT(*) FROM cards c WHERE c.agent_id=a.id) card_count,
      (SELECT COUNT(*) FROM agents x WHERE x.parent_id=a.id) child_count
    FROM agents a LEFT JOIN agents p ON p.id=a.parent_id ${w}
    ORDER BY a.id DESC LIMIT ? OFFSET ?`).all(...a, lim, off);
  ok(res, { total, list });
}));

app.post('/api/admin/agents', authAdmin, safe((req, res) => {
  const { username, password, nickname, contact, level, balance, parent_id } = req.body || {};
  if (!username || !password) return fail(res, 400, '账号密码必填');
  const salt = require('crypto').randomBytes(8).toString('hex');
  const apiKey = 'AK' + require('crypto').randomBytes(16).toString('hex').toUpperCase();
  try {
    db.prepare(`INSERT INTO agents(username,password_hash,salt,nickname,contact,parent_id,level,balance,api_key,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .run(username, hashPassword(password, salt), salt, nickname || '', contact || '',
        parent_id || null, parseInt(level, 10) || 1,
        parseFloat(balance) || 0, apiKey, now());
    ok(res, { api_key: apiKey }, '代理创建成功');
  } catch (e) { fail(res, 400, '账号已存在'); }
}));

app.put('/api/admin/agents/:id', authAdmin, safe((req, res) => {
  const { nickname, contact, level, frozen, remark } = req.body || {};
  db.prepare('UPDATE agents SET nickname=?,contact=?,level=?,frozen=? WHERE id=?')
    .run(nickname || '', contact || '', parseInt(level, 10) || 1,
      frozen ? 1 : 0, req.params.id);
  ok(res, {}, '已更新');
}));

app.post('/api/admin/agents/:id/balance', authAdmin, safe((req, res) => {
  const delta = parseFloat(req.body.delta) || 0;
  const a = db.prepare('SELECT * FROM agents WHERE id=?').get(req.params.id);
  if (!a) return fail(res, 404, '代理不存在');
  const nb = +(a.balance + delta).toFixed(2);
  db.prepare('UPDATE agents SET balance=? WHERE id=?').run(nb, a.id);
  db.prepare(`INSERT INTO agent_logs(agent_id,delta,balance,type,remark,created_at)
    VALUES(?,?,?, 'manual',?,?)`).run(a.id, delta, nb, delta > 0 ? '管理员加款' : '管理员扣款', now());
  ok(res, { balance: nb }, `操作成功，余额 ¥${nb}`);
}));

app.post('/api/admin/agents/:id/resetpwd', authAdmin, safe((req, res) => {
  const np = req.body.password || '123456';
  const salt = require('crypto').randomBytes(8).toString('hex');
  db.prepare('UPDATE agents SET password_hash=?, salt=? WHERE id=?')
    .run(hashPassword(np, salt), salt, req.params.id);
  ok(res, {}, `密码已重置为 ${np}`);
}));

app.delete('/api/admin/agents/:id', authAdmin, safe((req, res) => {
  db.prepare('DELETE FROM agents WHERE id=?').run(req.params.id);
  ok(res, {}, '已删除');
}));

app.get('/api/admin/agents/:id/logs', authAdmin, safe((req, res) => {
  ok(res, { list: db.prepare('SELECT * FROM agent_logs WHERE agent_id=? ORDER BY id DESC LIMIT 200').all(req.params.id) });
}));

/* ---- 提现 ---- */
app.get('/api/admin/withdrawals', authAdmin, safe((req, res) => {
  ok(res, {
    list: db.prepare(`SELECT w.*, a.username FROM withdrawals w
      LEFT JOIN agents a ON a.id=w.agent_id ORDER BY w.id DESC LIMIT 300`).all()
  });
}));

app.post('/api/admin/withdrawals/:id', authAdmin, safe((req, res) => {
  const { status, remark } = req.body || {}; // paid | rejected
  const w = db.prepare('SELECT * FROM withdrawals WHERE id=?').get(req.params.id);
  if (!w) return fail(res, 404, '记录不存在');
  if (w.status !== 'pending') return fail(res, 400, '该申请已处理');
  db.prepare('UPDATE withdrawals SET status=?, remark=?, handled_at=? WHERE id=?')
    .run(status, remark || '', now(), w.id);
  if (status === 'rejected') {
    // 驳回则退回余额
    const a = db.prepare('SELECT * FROM agents WHERE id=?').get(w.agent_id);
    const nb = +(a.balance + w.amount).toFixed(2);
    db.prepare('UPDATE agents SET balance=? WHERE id=?').run(nb, a.id);
    db.prepare(`INSERT INTO agent_logs(agent_id,delta,balance,type,remark,created_at)
      VALUES(?,?,?, 'withdraw',?,?)`).run(a.id, w.amount, nb, '提现驳回退回', now());
  }
  ok(res, {}, '已处理');
}));

/* ---- 验证日志 ---- */
app.get('/api/admin/logs', authAdmin, safe((req, res) => {
  const { page = 1, size = 30, kw = '', action = '', onlyFail = '' } = req.query;
  const lim = Math.min(500, parseInt(size, 10) || 30);
  const off = (Math.max(1, parseInt(page, 10) || 1) - 1) * lim;
  const w = []; const a = [];
  if (kw) { w.push('(card_key LIKE ? OR device_id LIKE ? OR ip LIKE ?)'); a.push(`%${kw}%`, `%${kw}%`, `%${kw}%`); }
  if (action) { w.push('action=?'); a.push(action); }
  if (onlyFail === '1') w.push('ok=0');
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) c FROM verify_logs ${where}`).get(...a).c;
  const list = db.prepare(`SELECT * FROM verify_logs ${where} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(...a, lim, off)
    .map(r => ({ ...r, time_text: new Date(r.created_at).toLocaleString('zh-CN') }));
  ok(res, { total, list });
}));

/* ---- 系统设置 ---- */
app.get('/api/admin/settings', authAdmin, safe((req, res) => {
  const rows = db.prepare('SELECT k,v FROM settings').all();
  const o = {};
  for (const r of rows) o[r.k] = r.v;
  ok(res, { settings: o });
}));

app.post('/api/admin/settings', authAdmin, safe((req, res) => {
  const s = req.body || {};
  const allow = ['site_name', 'card_prefix', 'bind_device', 'sign_required', 'heart_interval',
    'recharge_rate', 'client_ver', 'download_url', 'allow_rebind', 'notice',
    'self_unbind'];
  for (const k of allow) if (k in s) setSetting(k, s[k]);
  ok(res, {}, '设置已保存');
}));

app.post('/api/admin/secret/rotate', authAdmin, safe((req, res) => {
  const s = require('crypto').randomBytes(24).toString('hex');
  setSetting('api_secret', s);
  ok(res, { api_secret: s }, '密钥已重置，请同步更新客户端');
}));

/* ---- 公告 ---- */
app.get('/api/admin/notices', authAdmin, safe((req, res) => {
  ok(res, { list: db.prepare('SELECT * FROM notices ORDER BY id DESC').all() });
}));
app.post('/api/admin/notices', authAdmin, safe((req, res) => {
  const { title, content, ver, force, enabled } = req.body || {};
  db.prepare('INSERT INTO notices(title,content,ver,force,enabled,created_at) VALUES(?,?,?,?,?,?)')
    .run(title || '', content || '', ver || '', force ? 1 : 0, enabled ? 1 : 0, now());
  ok(res, {}, '已发布');
}));
app.delete('/api/admin/notices/:id', authAdmin, safe((req, res) => {
  db.prepare('DELETE FROM notices WHERE id=?').run(req.params.id);
  ok(res, {}, '已删除');
}));

/* ---- 数据库备份 ---- */
app.get('/api/admin/backup', authAdmin, safe((req, res) => {
  const file = path.join(__dirname, '..', 'data', 'cardauth.db');
  db.pragma('wal_checkpoint(TRUNCATE)');
  res.download(file, `cardauth-backup-${Date.now()}.db`);
}));

/* =====================================================================
 *  三、代理后台接口 /api/agent/*
 * ===================================================================== */
app.post('/api/agent/login', loginLimiter, safe((req, res) => {
  const { username, password } = req.body || {};
  const a = db.prepare('SELECT * FROM agents WHERE username=?').get(username || '');
  if (!a) return fail(res, 401, '账号或密码错误');
  if (hashPassword(password || '', a.salt) !== a.password_hash) return fail(res, 401, '账号或密码错误');
  if (a.frozen) return fail(res, C.CODE.AGENT_FROZEN, '账号已被冻结');
  const token = jwt.sign({ id: a.id, role: 'agent', username: a.username }, getSetting('jwt_secret'), { expiresIn: '12h' });
  ok(res, { token, username: a.username, nickname: a.nickname });
}));

app.get('/api/agent/me', authAgent, safe((req, res) => {
  const a = req.agent;
  const q = (s, ...p) => db.prepare(s).get(...p);
  ok(res, {
    agent: {
      id: a.id, username: a.username, nickname: a.nickname, contact: a.contact,
      level: a.level, balance: a.balance, api_key: a.api_key,
      parent_id: a.parent_id,
    },
    stats: {
      card_total: q('SELECT COUNT(*) c FROM cards WHERE agent_id=?', a.id).c,
      card_unused: q("SELECT COUNT(*) c FROM cards WHERE agent_id=? AND status='unused'", a.id).c,
      card_used: q("SELECT COUNT(*) c FROM cards WHERE agent_id=? AND status='used'", a.id).c,
      child_count: q('SELECT COUNT(*) c FROM agents WHERE parent_id=?', a.id).c,
    },
    apps: db.prepare('SELECT app_id,name FROM apps WHERE enabled=1 ORDER BY id').all(),
    types: db.prepare('SELECT app_id,code,name,unit,value FROM card_types WHERE enabled=1 ORDER BY app_id, unit, sort').all(),
  });
}));

app.post('/api/agent/cards/generate', authAgent, safe((req, res) => {
  const { type_code, count, max_devices, remark, app_id, type_value } = req.body || {};
  const r = C.generateCards({
    typeCode: type_code, count, agentId: req.agent.id,
    maxDevices: parseInt(max_devices, 10) || 1, remark: remark || '',
    appId: app_id || 'default',
    typeValue: type_value,
  });
  if (!r.ok) return fail(res, r.code, r.msg);
  ok(res, r, `成功生成 ${r.count} 张`);
}));

app.get('/api/agent/cards', authAgent, safe((req, res) => {
  const { page = 1, size = 20, status = '' } = req.query;
  const lim = Math.min(500, parseInt(size, 10) || 20);
  const off = (Math.max(1, parseInt(page, 10) || 1) - 1) * lim;
  const w = ['agent_id=?']; const a = [req.agent.id];
  if (status) { w.push('status=?'); a.push(status); }
  const where = 'WHERE ' + w.join(' AND ');
  const total = db.prepare(`SELECT COUNT(*) c FROM cards ${where}`).get(...a).c;
  const list = db.prepare(`SELECT c.*, ap.name app_name FROM cards c
    LEFT JOIN apps ap ON ap.app_id=c.app_id ${where} ORDER BY c.id DESC LIMIT ? OFFSET ?`)
    .all(...a, lim, off);
  ok(res, { total, list });
}));

app.get('/api/agent/logs', authAgent, safe((req, res) => {
  ok(res, { list: db.prepare('SELECT * FROM agent_logs WHERE agent_id=? ORDER BY id DESC LIMIT 200').all(req.agent.id) });
}));

app.post('/api/agent/withdraw', authAgent, safe((req, res) => {
  const amount = parseFloat(req.body.amount);
  const account = String(req.body.account || '').trim();
  if (!amount || amount <= 0) return fail(res, 400, '金额错误');
  if (!account) return fail(res, 400, '请填写收款账号');
  const a = req.agent;
  if (a.balance < amount) return fail(res, C.CODE.AGENT_BALANCE, `余额不足，当前 ¥${a.balance}`);
  const nb = +(a.balance - amount).toFixed(2);
  db.prepare('UPDATE agents SET balance=? WHERE id=?').run(nb, a.id);
  db.prepare('INSERT INTO withdrawals(agent_id,amount,account,status,created_at) VALUES(?,?,?,?,?)')
    .run(a.id, amount, account, 'pending', now());
  db.prepare(`INSERT INTO agent_logs(agent_id,delta,balance,type,remark,created_at)
    VALUES(?,?,?, 'withdraw',?,?)`).run(a.id, -amount, nb, '提现申请', now());
  ok(res, { balance: nb }, '提现申请已提交，等待审核');
}));

app.get('/api/agent/withdrawals', authAgent, safe((req, res) => {
  ok(res, { list: db.prepare('SELECT * FROM withdrawals WHERE agent_id=? ORDER BY id DESC LIMIT 100').all(req.agent.id) });
}));

/** 代理注册（可开放给下线的注册端） */
app.post('/api/agent/register', loginLimiter, safe((req, res) => {
  if (getSetting('agent_register_open', '1') === '0') return fail(res, 403, '代理注册已关闭');
  const { username, password, nickname, contact, parent_username } = req.body || {};
  if (!username || !password) return fail(res, 400, '账号密码必填');
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return fail(res, 400, '账号需3-20位字母数字下划线');
  if (String(password).length < 6) return fail(res, 400, '密码至少6位');
  let parentId = null;
  if (parent_username) {
    const p = db.prepare('SELECT * FROM agents WHERE username=?').get(parent_username);
    if (!p) return fail(res, 400, '上级代理不存在');
    if (p.frozen) return fail(res, 400, '上级代理已冻结');
    parentId = p.id;
  }
  const salt = require('crypto').randomBytes(8).toString('hex');
  const apiKey = 'AK' + require('crypto').randomBytes(16).toString('hex').toUpperCase();
  try {
    db.prepare(`INSERT INTO agents(username,password_hash,salt,nickname,contact,parent_id,level,balance,api_key,created_at)
      VALUES(?,?,?,?,?,?,1,0,?,?)`)
      .run(username, hashPassword(password, salt), salt, nickname || username, contact || '',
        parentId, apiKey, now());
    ok(res, { username, api_key: apiKey }, '注册成功，请登录代理后台');
  } catch (e) { fail(res, 400, '账号已存在'); }
}));

/* =====================================================================
 *  三半、网页端代签接口 /api/web/*
 *  浏览器里没法安全保存密钥，所以由服务端代签。
 *  这组接口只暴露「查询 / 兑换」两个低风险动作，充值必须在持有卡密的前提下进行。
 * ===================================================================== */
const webLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false,
  message: { code: 9003, msg: '操作过于频繁，请稍后再试' },
});

/** 网页查询卡密信息（不绑定设备，只读） */
app.post('/api/web/info', webLimiter, safe((req, res) => {
  const { card_key, device_id } = req.body || {};
  const cur = C.checkCard(card_key);
  if (!cur.ok) return res.json({ code: cur.code, msg: cur.msg });
  const u = C.ensureUser(cur.card.card_key);
  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'web_info', ok: true, code: 0, msg: '网页查询' });
  res.json({ code: 0, msg: 'ok', card: C.publicCard(cur.card, u) });
}));

/** 网页兑换充值：用额度卡给自己充值（需同时持有登录卡与充值卡） */
app.post('/api/web/redeem', webLimiter, safe((req, res) => {
  const { card_key, redeem_key, device_id } = req.body || {};

  const cur = C.checkCard(card_key);
  if (!cur.ok) return res.json({ code: cur.code, msg: cur.msg });

  const rk = String(redeem_key || '').trim().toUpperCase();
  if (!rk) return res.json({ code: C.CODE.PARAM_ERROR, msg: '缺少充值卡号' });
  const target = db.prepare('SELECT * FROM cards WHERE card_key=?').get(rk);
  if (!target) return res.json({ code: C.CODE.CARD_NOT_FOUND, msg: '充值卡不存在，请核对卡号' });
  if (target.unit === 'day') {
    return res.json({ code: 1005, msg: '这是时长卡（天/周/月卡），请在客户端里激活，不能用作额度充值' });
  }
  if (target.status === 'disabled') return res.json({ code: C.CODE.CARD_DISABLED, msg: '该充值卡已被封禁' });
  if (target.status !== 'unused') return res.json({ code: C.CODE.CARD_USED, msg: '该充值卡已被使用过' });
  if (target.card_key === cur.card.card_key) return res.json({ code: 1001, msg: '不能给自己充自己' });

  const amount = target.value;
  const t = now();
  let balance = 0;
  const tx = db.transaction(() => {
    db.prepare(`UPDATE cards SET status='used', activated_at=?, used_count=used_count+1 WHERE id=?`)
      .run(t, target.id);
    const r2 = C.changeCredit(cur.card.card_key, amount, 'card_redeem', target.card_key,
      `网页充值 ${target.type_name}`, clientIp(req));
    if (!r2.ok) throw new Error(r2.msg);
    balance = r2.balance;
  });
  try { tx(); }
  catch (e) { return res.json({ code: C.CODE.SERVER_ERROR, msg: e.message }); }

  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'web_redeem', ok: true, code: 0, msg: `网页充值 +${amount}` });
  res.json({ code: 0, msg: `充值成功，增加 ${amount} 额度`, add: amount, balance });
}));

/** 网页激活时长卡 */
app.post('/api/web/activate', webLimiter, safe((req, res) => {
  const { card_key, device_id } = req.body || {};
  const r = C.activateCard({ cardKey: card_key, deviceId: device_id, ip: clientIp(req) });
  C.logVerify({ cardKey: card_key, deviceId: device_id, ip: clientIp(req),
    action: 'web_activate', ok: r.ok, code: r.code, msg: r.msg });
  if (!r.ok) return res.json({ code: r.code, msg: r.msg, card: r.card || null });
  res.json({ code: 0, msg: r.msg, card: r.card });
}));

/** 查询某张卡已绑定的设备（自助解绑页用） */
app.post('/api/web/bindings', webLimiter, safe((req, res) => {
  const { card_key } = req.body || {};
  const cur = C.checkCard(card_key);
  if (!cur.ok) return res.json({ code: cur.code, msg: cur.msg });

  const devs = db.prepare(`SELECT device_id, ip, first_seen, last_seen
    FROM card_devices WHERE card_id=? ORDER BY last_seen DESC`).all(cur.card.id);

  const allowRebind = getSetting('allow_rebind', '0') === '1';
  const selfUnbind = getSetting('self_unbind', '1') === '1';

  res.json({
    code: 0, msg: 'ok',
    card_key: cur.card.card_key,
    type_name: cur.card.type_name,
    status: cur.card.status,
    max_devices: cur.card.max_devices || 1,
    allow_rebind: allowRebind,     // 是否允许用户自助解绑
    self_unbind: selfUnbind,       // 是否开放自助解绑功能
    devices: devs.map(d => ({
      device_id: d.device_id,
      ip: d.ip,
      first_seen_text: new Date(d.first_seen).toLocaleString('zh-CN'),
      last_seen_text: new Date(d.last_seen).toLocaleString('zh-CN'),
    })),
  });
}));

/** 自助解绑一台或多台设备 */
app.post('/api/web/unbind', webLimiter, safe((req, res) => {
  if (getSetting('self_unbind', '1') !== '1') {
    return res.json({ code: 403, msg: '管理员已关闭自助解绑，请联系客服处理' });
  }
  if (getSetting('allow_rebind', '1') !== '1') {
    return res.json({ code: 403, msg: '自助解绑未开启，请联系客服解绑' });
  }

  const { card_key, device_id } = req.body || {};
  const cur = C.checkCard(card_key);
  if (!cur.ok) return res.json({ code: cur.code, msg: cur.msg });

  const card = cur.card;
  if (!device_id) {
    // 不传 device_id = 解绑全部
    const n = db.prepare('SELECT COUNT(*) c FROM card_devices WHERE card_id=?').get(card.id).c;
    db.prepare('DELETE FROM card_devices WHERE card_id=?').run(card.id);
    db.prepare('UPDATE cards SET owner_device=NULL WHERE id=?').run(card.id);
    C.logVerify({ cardKey: card.card_key, deviceId: '(全部)', ip: clientIp(req),
      action: 'web_unbind_all', ok: true, code: 0, msg: `自助解绑全部 ${n} 台设备` });
    return res.json({ code: 0, msg: `已解绑全部 ${n} 台设备，现在可以在新设备上激活了` });
  }

  const one = db.prepare('SELECT * FROM card_devices WHERE card_id=? AND device_id=?')
    .get(card.id, device_id);
  if (!one) return res.json({ code: 2006, msg: '该设备不在绑定列表中' });

  db.prepare('DELETE FROM card_devices WHERE id=?').run(one.id);
  const left = db.prepare('SELECT COUNT(*) c FROM card_devices WHERE card_id=?').get(card.id).c;
  if (left === 0) {
    db.prepare('UPDATE cards SET owner_device=NULL WHERE id=?').run(card.id);
  } else {
    const first = db.prepare('SELECT device_id FROM card_devices WHERE card_id=? ORDER BY first_seen LIMIT 1')
      .get(card.id);
    db.prepare('UPDATE cards SET owner_device=? WHERE id=?').run(first ? first.device_id : null, card.id);
  }

  C.logVerify({ cardKey: card.card_key, deviceId: device_id, ip: clientIp(req),
    action: 'web_unbind', ok: true, code: 0, msg: '自助解绑成功' });
  res.json({ code: 0, msg: '解绑成功，现在可以在新设备上使用了', remaining: left });
}));

/* =====================================================================
 *  四、静态页面 + 启动
 * ===================================================================== */
/**
 * 静态资源解析：
 *   1) 本地运行  → 项目 public/ 目录
 *   2) pkg 单文件 EXE → 从打包快照读取，同时优先读 EXE 同目录的 public/（便于用户自行替换页面）
 */
const fsp = require('fs');
const PKG = typeof process.pkg !== 'undefined';

/** 磁盘上的 public 目录（EXE 同级 或 项目根目录） */
const DISK_PUB = PKG
  ? path.join(path.dirname(process.execPath), 'public')
  : path.join(__dirname, '..', 'public');
const SNAP_PUB = path.join(__dirname, '..', 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
};

function sendStatic(res, name) {
  // 先试磁盘（用户可覆盖），再试打包快照
  const candidates = [path.join(DISK_PUB, name), path.join(SNAP_PUB, name)];
  for (const f of candidates) {
    try {
      if (fsp.existsSync(f) && fsp.statSync(f).isFile()) {
        res.setHeader('Content-Type', MIME[path.extname(f).toLowerCase()] || 'application/octet-stream');
        // 彻底禁用缓存：避免用户浏览器一直用旧的坏版本
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        return res.send(fsp.readFileSync(f));
      }
    } catch (e) { /* 继续尝试下一个 */ }
  }
  return res.status(404).send('404 Not Found');
}

// 静态资源路由（显式列出，保证打包后可用）
app.get('/style.css', (req, res) => sendStatic(res, 'style.css'));
app.get('/common.js', (req, res) => sendStatic(res, 'common.js'));
app.get('/favicon.ico', (req, res) => sendStatic(res, 'favicon.ico'));

/* 健康检查：云平台用它判断服务是否存活 */
app.get(/^\/(health|healthz)$/, (req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'ok', uptime: Math.floor(process.uptime()), time: now(), version: '1.0.0' });
  } catch (e) {
    res.status(503).json({ status: 'error', msg: e.message });
  }
});

app.get('/', (req, res) => sendStatic(res, 'index.html'));
app.get('/admin', (req, res) => sendStatic(res, 'admin.html'));
app.get('/agent', (req, res) => sendStatic(res, 'agent.html'));
app.get('/register', (req, res) => sendStatic(res, 'register.html'));
app.get('/unbind', (req, res) => sendStatic(res, 'unbind.html'));
app.get('/diag', (req, res) => sendStatic(res, 'diag.html'));
app.get('/diag.html', (req, res) => sendStatic(res, 'diag.html'));
// 备用入口：用于绕过浏览器缓存的旧页面
app.get('/login', (req, res) => sendStatic(res, 'admin.html'));
app.get('/manage', (req, res) => sendStatic(res, 'admin.html'));

// 兜底：其它静态文件
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.method !== 'GET') return next();
  const name = req.path.replace(/^\//, '');
  if (name && !name.includes('..')) {
    const f1 = path.join(DISK_PUB, name);
    const f2 = path.join(SNAP_PUB, name);
    if (fsp.existsSync(f1) || fsp.existsSync(f2)) return sendStatic(res, name);
  }
  next();
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ code: 404, msg: '接口不存在' });
  res.status(404).send('404 Not Found');
});

function localIPs() {
  const nets = os.networkInterfaces();
  const out = [];
  for (const name of Object.keys(nets)) {
    for (const n of nets[name] || []) {
      if (n.family === 'IPv4' && !n.internal) out.push(n.address);
    }
  }
  return out;
}

const server = app.listen(PORT, HOST, () => {
  const ips = localIPs();
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════╗');
  console.log('  ║           卡 密 验 证 系 统  ·  已 启 动              ║');
  console.log('  ╚══════════════════════════════════════════════════════╝');
  console.log('');
  if (IS_CLOUD) {
    console.log('  运行模式   : 云端部署');
    console.log('  监听端口   : ' + PORT);
    console.log('  数据文件   : ' + DB_PATH);
    console.log('');
  } else {
    console.log('  ★ 用浏览器打开下面这个地址（推荐 Chrome / Edge）');
    console.log('');
    console.log('     管理后台 : http://127.0.0.1:' + PORT + '/admin');
    console.log('     用户首页 : http://127.0.0.1:' + PORT + '/');
    console.log('     代理后台 : http://127.0.0.1:' + PORT + '/agent');
    console.log('');
    if (ips.length) {
      console.log('  手机/其他设备（同一个 WiFi 下打开，用手机浏览器扫码或输入）:');
      for (const ip of ips) console.log('     http://' + ip + ':' + PORT + '/admin');
      console.log('');
    }
    console.log('  登录账号   : ' + (process.env.ADMIN_USER || 'admin') +
      ' / ' + (process.env.ADMIN_PWD || 'admin888') + '   ← 登录后请立即改密码');
    console.log('  数据文件   : ' + DB_PATH);
    console.log('  运行引擎   : ' + (db.engine || 'sqlite'));
    console.log('');
  }
  console.log('  通信密钥   : ' + getSetting('api_secret'));
  console.log('');
  console.log('  ─────────────────────────────────────────────────────');
  console.log('  这个窗口不要关！关掉窗口 = 服务停止。');
  console.log('  要停止服务：按 Ctrl+C 或直接关窗口。');
  console.log('  ─────────────────────────────────────────────────────');
  console.log('');
});

/* 优雅退出（云端重启/扩容时必须处理） */
function shutdown(sig) {
  console.log(`\n[shutdown] 收到 ${sig}，正在关闭...`);
  server.close(() => {
    try { db.pragma('wal_checkpoint(TRUNCATE)'); db.close(); } catch (e) {}
    console.log('[shutdown] 已安全退出');
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 8000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
