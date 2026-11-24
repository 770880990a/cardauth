'use strict';
/**
 * 核心业务逻辑：卡密生成 / 验证 / 激活 / 额度充值 / 消耗 / 设备绑定 / 代理分润
 */
const crypto = require('crypto');
const { db, now, getSetting, setSetting } = require('./db');

/* ============================================================
 * 错误码表（客户端务必按 code 分支处理，不要按 msg 文本判断）
 * ============================================================ */
const CODE = {
  OK: 0,
  PARAM_ERROR: 1001,
  SIGN_ERROR: 1002,        // 签名错误（前端被改包/密钥不对/时间戳过期）
  REPLAY: 1003,            // 重放攻击（nonce 重复）
  TIMEOUT: 1004,           // 请求时间戳偏差过大
  CARD_NOT_FOUND: 2001,
  CARD_USED: 2002,         // 卡密已被使用
  CARD_DISABLED: 2003,     // 卡密被封禁
  CARD_EXPIRED: 2004,      // 卡密已过期
  CARD_NOT_ACTIVATED: 2005,// 卡密未激活
  DEVICE_MISMATCH: 2006,   // 设备不匹配（已绑定其它机器）
  DEVICE_LIMIT: 2007,      // 绑定设备数超限
  CREDIT_NOT_ENOUGH: 2008, // 额度不足
  TYPE_NOT_FOUND: 3001,
  TYPE_DISABLED: 3002,
  APP_NOT_FOUND: 3100,     // 应用不存在或已停用
  APP_DISABLED: 3101,
  AGENT_NOT_FOUND: 4001,
  AGENT_FROZEN: 4002,
  AGENT_BALANCE: 4003,     // 代理余额不足
  AGENT_PASSWORD: 4004,
  BANNED: 5001,            // 用户被封禁
  SERVER_ERROR: 9001,
  MAINTENANCE: 9002,       // 系统维护中
};

/* ============================================================
 * 卡密生成
 * ============================================================ */
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 去掉易混淆 0O1I

function randChars(n) {
  const bytes = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHABET[bytes[i] % ALPHABET.length];
  return s;
}

/** 生成形如 XXXX-XXXX-XXXX-XXXX 的卡密 */
function genCardKey(groups = 4, len = 4, prefix = '') {
  const parts = [];
  for (let i = 0; i < groups; i++) parts.push(randChars(len));
  return prefix + parts.join('-');
}

/**
 * 批量生成卡密
 *
 * @param {number} typeValue 手动指定面值。额度卡/次数卡必填（覆盖类型里的值），
 *                           时长卡可空（用类型定义的天数）
 */
function generateCards({ typeCode, count = 1, agentId = null, maxDevices = 1,
                         remark = '', batchNo = null, appId = 'default', typeValue = null }) {
  const type = db.prepare('SELECT * FROM card_types WHERE app_id=? AND code=? AND enabled=1').get(appId, typeCode);
  if (!type) return { ok: false, code: CODE.TYPE_NOT_FOUND, msg: '卡类型不存在或已禁用' };

  // 计算最终面值
  let faceValue = type.value;
  if (typeValue !== null && typeValue !== undefined && typeValue !== '') {
    const v = parseInt(typeValue, 10);
    if (isNaN(v) || v <= 0) {
      return { ok: false, code: CODE.PARAM_ERROR, msg: '面值必须是大于 0 的整数' };
    }
    if (v > 100000000) {
      return { ok: false, code: CODE.PARAM_ERROR, msg: '面值过大（上限 1 亿）' };
    }
    faceValue = v;
  } else if (type.unit === 'credit' && !type.value) {
    // 额度卡且类型没预设值 → 必须手动填
    return {
      ok: false, code: CODE.PARAM_ERROR,
      msg: `生成${type.name}时必须填写额度数量`,
    };
  }
  if (faceValue <= 0) {
    return { ok: false, code: CODE.PARAM_ERROR, msg: '面值必须大于 0' };
  }

  count = Math.max(1, Math.min(10000, parseInt(count, 10) || 1));
  const batch = batchNo || 'B' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + randChars(4);
  const t = now();

  let agent = null;
  if (agentId) {
    agent = db.prepare('SELECT * FROM agents WHERE id=?').get(agentId);
    if (!agent) return { ok: false, code: CODE.AGENT_NOT_FOUND, msg: '代理不存在' };
    if (agent.frozen) return { ok: false, code: CODE.AGENT_FROZEN, msg: '代理已被冻结' };
  }

  const insCard = db.prepare(`INSERT INTO cards
    (app_id,card_key,type_code,type_name,unit,value,remain,status,agent_id,batch_no,max_devices,remark,created_at)
    VALUES(?,?,?,?,?,?,?, 'unused', ?,?,?,?,?)`);
  const keys = [];
  const prefix = getSetting('card_prefix', '');

  const tx = db.transaction(() => {
    let tries = 0;
    while (keys.length < count && tries < count * 20) {
      tries++;
      const k = genCardKey(4, 4, prefix);
      try {
        // 时长卡（hour/day）remain=0，用 expire_at 计时；额度卡 remain=面值
        insCard.run(appId, k, type.code, type.name, type.unit, faceValue,
          type.unit === 'credit' ? faceValue : 0,
          agentId, batch, maxDevices, remark, t);
        keys.push(k);
      } catch (e) { /* 唯一冲突，重试 */ }
    }
    if (agentId) {
      db.prepare(`INSERT INTO agent_logs(agent_id,delta,balance,type,ref,remark,created_at)
        VALUES(?,?,?, 'generate', ?,?,?)`)
        .run(agentId, 0, agent.balance, batch, `生成${keys.length}张 ${type.name}`, t);
    }
  });
  tx();

  return {
    ok: true, code: CODE.OK, batch, count: keys.length, cards: keys,
    app_id: appId, unit: type.unit, face_value: faceValue, type_name: type.name,
  };
}

/* ============================================================
 * 签名校验（HMAC-SHA256）
 * sign = HMAC_SHA256(secret, card_key + device_id + timestamp + nonce + body_json)
 * ============================================================ */
const nonceCache = new Map(); // nonce -> expireAt
function cleanNonce() {
  const t = now();
  for (const [k, v] of nonceCache) if (v < t) nonceCache.delete(k);
}
setInterval(cleanNonce, 60 * 1000).unref();

function hmac(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * 校验签名
 * @param {object} p  请求参数
 * @param {string} rawBody 原始 body（JSON 字符串规范化后参与签名）
 */
function checkSign(p, rawBody = '') {
  // 取密钥：优先用请求里带的 app_id 对应应用的密钥，没有再回退全局密钥
  let secret = null;
  if (p.app_id) {
    const app = db.prepare('SELECT secret FROM apps WHERE app_id=? AND enabled=1').get(String(p.app_id));
    if (!app) return { ok: false, code: CODE.APP_NOT_FOUND, msg: '应用不存在或已停用' };
    secret = app.secret;
  }
  if (!secret) secret = getSetting('api_secret');
  if (!secret) return { ok: true }; // 未配置密钥则不校验（不推荐）

  const ts = parseInt(p.timestamp, 10);
  if (!p.sign) return { ok: false, code: CODE.SIGN_ERROR, msg: '缺少 sign 签名参数' };
  if (!ts) return { ok: false, code: CODE.PARAM_ERROR, msg: '缺少 timestamp 时间戳' };
  if (!p.nonce) return { ok: false, code: CODE.PARAM_ERROR, msg: '缺少 nonce 随机串' };

  // 时间偏差 5 分钟
  if (Math.abs(now() - ts) > 5 * 60 * 1000) {
    return { ok: false, code: CODE.TIMEOUT, msg: '请求时间戳偏差过大，请校准本机时间' };
  }
  // 重放
  if (nonceCache.has(p.nonce)) return { ok: false, code: CODE.REPLAY, msg: '重复请求(nonce已使用)' };

  const payload = [
    p.card_key || '', p.device_id || '', p.timestamp, p.nonce, rawBody || ''
  ].join('|');
  const expect = hmac(secret, payload);
  const got = String(p.sign).toLowerCase();
  const a = Buffer.from(expect, 'utf8');
  const b = Buffer.from(got, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, code: CODE.SIGN_ERROR, msg: '签名校验失败' };
  }
  nonceCache.set(p.nonce, now() + 10 * 60 * 1000);
  return { ok: true, code: CODE.OK };
}

/* ============================================================
 * 日志
 * ============================================================ */
function logVerify({ cardKey, deviceId, ip, action, ok, code, msg, raw }) {
  try {
    db.prepare(`INSERT INTO verify_logs(card_key,device_id,ip,action,ok,code,msg,raw,created_at)
      VALUES(?,?,?,?,?,?,?,?,?)`)
      .run(cardKey || '', deviceId || '', ip || '', action, ok ? 1 : 0, code, msg || '',
        raw ? String(raw).slice(0, 500) : '', now());
  } catch (e) { /* 日志失败不影响主流程 */ }
}

/* ============================================================
 * 设备绑定
 * ============================================================ */
function bindDevice(card, deviceId, ip) {
  const bindOn = getSetting('bind_device', '1') === '1';
  if (!bindOn || !deviceId) return { ok: true };

  const t = now();
  const exist = db.prepare('SELECT * FROM card_devices WHERE card_id=? AND device_id=?')
    .get(card.id, deviceId);

  if (exist) {
    db.prepare('UPDATE card_devices SET last_seen=?, ip=? WHERE id=?').run(t, ip || '', exist.id);
    return { ok: true };
  }

  const cnt = db.prepare('SELECT COUNT(*) c FROM card_devices WHERE card_id=?').get(card.id).c;
  const limit = card.max_devices || 1;
  if (cnt >= limit) {
    return {
      ok: false, code: CODE.DEVICE_LIMIT,
      msg: `该卡密已绑定 ${cnt} 台设备，上限 ${limit} 台。如需换机请联系客服解绑。`
    };
  }
  db.prepare('INSERT INTO card_devices(card_id,device_id,ip,first_seen,last_seen) VALUES(?,?,?,?,?)')
    .run(card.id, deviceId, ip || '', t, t);

  if (!card.owner_device) {
    db.prepare('UPDATE cards SET owner_device=? WHERE id=?').run(deviceId, card.id);
  }
  return { ok: true };
}

/* ============================================================
 * 用户表（额度账户）—— 以卡密为主键
 * ============================================================ */
function ensureUser(cardKey) {
  const t = now();
  let u = db.prepare('SELECT * FROM users WHERE card_key=?').get(cardKey);
  if (!u) {
    db.prepare(`INSERT INTO users(card_key,credit,total_credit,used_credit,expire_at,vip_level,ban,created_at,updated_at)
      VALUES(?,0,0,0,NULL,0,0,?,?)`).run(cardKey, t, t);
    u = db.prepare('SELECT * FROM users WHERE card_key=?').get(cardKey);
  }
  return u;
}

/**
 * 额度变动（原子操作）
 * @param {number} delta 正数充值，负数消耗
 */
function changeCredit(cardKey, delta, source, ref = '', remark = '', ip = '') {
  const tx = db.transaction(() => {
    const u = ensureUser(cardKey);
    const nb = u.credit + delta;
    if (nb < 0) return { ok: false, code: CODE.CREDIT_NOT_ENOUGH, msg: `额度不足，当前 ${u.credit}` };

    const totalInc = delta > 0 ? delta : 0;
    const usedInc = delta < 0 ? -delta : 0;
    db.prepare(`UPDATE users SET credit=?, total_credit=total_credit+?, used_credit=used_credit+?, updated_at=?
      WHERE card_key=?`).run(nb, totalInc, usedInc, now(), cardKey);
    db.prepare(`INSERT INTO credits_log(card_key,delta,balance,source,ref,remark,ip,created_at)
      VALUES(?,?,?,?,?,?,?,?)`).run(cardKey, delta, nb, source, ref, remark, ip, now());
    return { ok: true, code: CODE.OK, balance: nb, delta };
  });
  return tx();
}

/* ============================================================
 * 卡密状态检查（公共）
 * ============================================================ */
function checkCard(cardKey) {
  if (!cardKey) return { ok: false, code: CODE.PARAM_ERROR, msg: '缺少卡密' };
  const key = String(cardKey).trim().toUpperCase();
  const card = db.prepare('SELECT * FROM cards WHERE card_key=?').get(key);
  if (!card) return { ok: false, code: CODE.CARD_NOT_FOUND, msg: '卡密不存在' };
  if (card.status === 'disabled') return { ok: false, code: CODE.CARD_DISABLED, msg: '卡密已被封禁' };
  if (card.status === 'used') {
    if (card.expire_at && card.expire_at < now()) {
      return { ok: false, code: CODE.CARD_EXPIRED, msg: '卡密已过期', card };
    }
  }
  return { ok: true, card };
}

/* ============================================================
 * 激活卡密（天卡/周卡/月卡 → 加时长；额度卡 → 加额度）
 * ============================================================ */
function activateCard({ cardKey, deviceId, ip }) {
  const r = checkCard(cardKey);
  if (!r.ok) return r;
  const card = r.card;
  const key = card.card_key;
  const t = now();

  // 设备绑定
  const b = bindDevice(card, deviceId, ip);
  if (!b.ok) return b;

  // 已使用：返回现有状态（幂等，允许客户端重复调用）
  if (card.status === 'used') {
    const u = ensureUser(key);
    return {
      ok: true, code: CODE.OK, msg: '卡密已激活', card: publicCard(card, u), already: true
    };
  }

  const tx = db.transaction(() => {
    const u = ensureUser(key);

    if (card.unit === 'day' || card.unit === 'hour') {
      // 时长卡：从"当前到期时间或现在"中较晚者开始累加
      const base = (u.expire_at && u.expire_at > t) ? u.expire_at : t;
      const msPerUnit = card.unit === 'hour' ? 3600000 : 86400000;
      const exp = base + card.value * msPerUnit;
      db.prepare('UPDATE users SET expire_at=?, vip_level=vip_level+1, updated_at=? WHERE card_key=?')
        .run(exp, t, key);
      db.prepare(`UPDATE cards SET status='used', activated_at=?, expire_at=?, used_count=used_count+1,
        owner_device=COALESCE(owner_device,?) WHERE id=?`)
        .run(t, exp, deviceId || null, card.id);
    } else {
      // 额度卡：直接加额度
      const rate = parseFloat(getSetting('recharge_rate', '1')) || 1;
      const add = Math.floor(card.value * rate);
      db.prepare(`UPDATE users SET credit=credit+?, total_credit=total_credit+?, updated_at=? WHERE card_key=?`)
        .run(add, add, t, key);
      const nu = db.prepare('SELECT * FROM users WHERE card_key=?').get(key);
      db.prepare(`INSERT INTO credits_log(card_key,delta,balance,source,ref,remark,ip,created_at)
        VALUES(?,?,?, 'card_redeem', ?,?,?,?)`)
        .run(key, add, nu.credit, key, `卡密充值 ${card.type_name}`, ip || '', t);
      db.prepare(`UPDATE cards SET status='used', activated_at=?, remain=0, used_count=used_count+1,
        owner_device=COALESCE(owner_device,?) WHERE id=?`)
        .run(t, deviceId || null, card.id);
    }
    return true;
  });
  tx();

  const card2 = db.prepare('SELECT * FROM cards WHERE id=?').get(card.id);
  const u2 = ensureUser(key);
  return { ok: true, code: CODE.OK, msg: '激活成功', card: publicCard(card2, u2) };
}

/** 对外输出结构 */
function publicCard(card, user) {
  const u = user || ensureUser(card.card_key);
  const devs = db.prepare('SELECT device_id, first_seen, last_seen FROM card_devices WHERE card_id=?')
    .all(card.id);

  const isTime = card.unit === 'day' || card.unit === 'hour';
  const t = now();

  // 剩余时长（小时卡按小时算，天卡按天算）
  let remainHours = null, remainDays = null;
  if (isTime && card.expire_at) {
    const leftMs = Math.max(0, card.expire_at - t);
    remainHours = Math.ceil(leftMs / 3600000);
    remainDays = Math.ceil(leftMs / 86400000);
  }
  let uRemainHours = null, uRemainDays = 0;
  if (u.expire_at) {
    const leftMs = Math.max(0, u.expire_at - t);
    uRemainHours = Math.ceil(leftMs / 3600000);
    uRemainDays = Math.ceil(leftMs / 86400000);
  }

  return {
    card_key: card.card_key,
    app_id: card.app_id,
    type_code: card.type_code,
    type_name: card.type_name,
    unit: card.unit,
    value: card.value,
    status: card.status,
    activated_at: card.activated_at,
    expire_at: card.expire_at,
    expire_at_text: card.expire_at ? new Date(card.expire_at).toLocaleString('zh-CN') : null,
    // 时长卡：小时卡返回小时和天数，天卡只返回天数
    remain_hours: (card.unit === 'hour' && card.expire_at) ? remainHours : null,
    remain_days: (card.unit === 'day' && card.expire_at) ? remainDays : null,
    max_devices: card.max_devices,
    devices: devs,
    user: {
      credit: u.credit,
      total_credit: u.total_credit,
      used_credit: u.used_credit,
      expire_at: u.expire_at,
      expire_at_text: u.expire_at ? new Date(u.expire_at).toLocaleString('zh-CN') : null,
      remain_hours: uRemainHours,
      remain_days: uRemainDays,
      is_vip: !!(u.expire_at && u.expire_at > t),
      ban: u.ban,
    },
  };
}

/* ============================================================
 * 验证（登录态校验 / 心跳）
 * ============================================================ */
function verifyCard({ cardKey, deviceId, ip }) {
  const r = checkCard(cardKey);
  if (!r.ok) return r;
  const card = r.card;

  if (card.status === 'unused') {
    return { ok: false, code: CODE.CARD_NOT_ACTIVATED, msg: '卡密未激活，请先激活', card: publicCard(card) };
  }

  const b = bindDevice(card, deviceId, ip);
  if (!b.ok) return b;

  const u = ensureUser(card.card_key);
  if (u.ban) return { ok: false, code: CODE.BANNED, msg: '账号已被封禁' };

  // 时长卡（小时卡/天卡）过期判定
  if (card.unit === 'day' || card.unit === 'hour') {
    if (!u.expire_at || u.expire_at < now()) {
      db.prepare(`UPDATE cards SET status='expired' WHERE id=?`).run(card.id);
      return { ok: false, code: CODE.CARD_EXPIRED, msg: '会员已到期，请续费', card: publicCard(card, u) };
    }
  }

  // 额度卡：额度为 0 也允许登录（可能后续充值）
  return { ok: true, code: CODE.OK, msg: '验证通过', card: publicCard(card, u) };
}

/* ============================================================
 * 消耗额度
 * ============================================================ */
function consumeCredit({ cardKey, amount = 1, deviceId, ip, remark = '' }) {
  const r = checkCard(cardKey);
  if (!r.ok) return r;
  const b = bindDevice(r.card, deviceId, ip);
  if (!b.ok) return b;

  const amt = Math.max(1, parseInt(amount, 10) || 1);
  const res = changeCredit(r.card.card_key, -amt, 'api_consume', '', remark, ip);
  if (!res.ok) return res;
  return { ok: true, code: CODE.OK, msg: '扣费成功', balance: res.balance, cost: amt };
}

/* ============================================================
 * 代理分润（下级生成卡时，给上级返差价）
 * ============================================================ */
function agentProfit(childAgentId, amount, ref) {
  const child = db.prepare('SELECT * FROM agents WHERE id=?').get(childAgentId);
  if (!child || !child.parent_id) return;
  const parent = db.prepare('SELECT * FROM agents WHERE id=?').get(child.parent_id);
  if (!parent) return;
  const t = now();
  const nb = +(parent.balance + amount).toFixed(2);
  db.prepare('UPDATE agents SET balance=? WHERE id=?').run(nb, parent.id);
  db.prepare(`INSERT INTO agent_logs(agent_id,delta,balance,type,ref,remark,created_at)
    VALUES(?,?,?, 'profit', ?,?,?)`)
    .run(parent.id, amount, nb, ref, `下级 #${childAgentId} 生成卡分润`, t);
}

module.exports = {
  CODE, genCardKey, generateCards, checkSign, hmac,
  logVerify, bindDevice, ensureUser, changeCredit, checkCard,
  activateCard, verifyCard, consumeCredit, publicCard, agentProfit, randChars,
};
