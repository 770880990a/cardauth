/**
 * 释然团队 · 卡密系统 —— 纯前端本地版
 * ---------------------------------------------------
 * 跑在 GitHub Pages / 任何静态托管上，不需要服务器
 * 数据存在浏览器 IndexedDB 里（你的浏览器 = 你的数据库）
 *
 * 核心思路：拦截所有 fetch('/api/...') 请求，用本地函数处理并返回
 */

(function () {
  'use strict';

  /* ===================== 工具函数 ===================== */

  function now() { return Date.now(); }

  function randChars(n, chars) {
    chars = chars || 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    let s = '';
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    for (let i = 0; i < n; i++) s += chars[a[i] % chars.length];
    return s;
  }

  function randHex(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function genCardKey(seg, groups, prefix) {
    seg = seg || 4; groups = groups || 4;
    const parts = [];
    for (let i = 0; i < groups; i++) parts.push(randChars(seg));
    return (prefix || '') + parts.join('-');
  }

  async function sha256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function hmac(secret, msg) {
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function hashPassword(pwd, salt) { return sha256(salt + '::' + pwd + '::cardauth'); }

  /* ===================== IndexedDB ===================== */

  const DB_NAME = 'shiran_cardauth';
  const DB_VER = 1;
  const STORES = ['admins', 'apps', 'card_types', 'cards', 'card_devices', 'users',
    'credits_log', 'agents', 'agent_logs', 'withdrawals', 'verify_logs', 'notices', 'settings'];

  let dbPromise = null;

  function openDB() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VER);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        for (const s of STORES) {
          if (!db.objectStoreNames.contains(s)) {
            const store = db.createObjectStore(s, { keyPath: 'id', autoIncrement: true });
            if (s === 'cards') {
              store.createIndex('card_key', 'card_key', { unique: true });
              store.createIndex('app_id', 'app_id');
              store.createIndex('status', 'status');
            }
            if (s === 'card_types') store.createIndex('app_key', ['app_id', 'code'], { unique: true });
            if (s === 'users') store.createIndex('card_key', 'card_key', { unique: true });
            if (s === 'card_devices') store.createIndex('card_id', 'card_id');
            if (s === 'apps') store.createIndex('app_id', 'app_id', { unique: true });
            if (s === 'agents') store.createIndex('username', 'username', { unique: true });
            if (s === 'settings') store.createIndex('k', 'k', { unique: true });
            if (s === 'notices') store.createIndex('created_at', 'created_at');
            if (s === 'credits_log') store.createIndex('card_key', 'card_key');
          }
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return dbPromise;
  }

  async function tx(storeNames, mode, fn) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(storeNames, mode);
      let result;
      t.oncomplete = () => resolve(result);
      t.onerror = () => reject(t.error);
      try {
        result = fn(t);
        if (result && typeof result.then === 'function') {
          result.then(r => { result = r; }).catch(reject);
        }
      } catch (e) { reject(e); }
    });
  }

  function reqToPromise(req) {
    return new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function getAll(store) {
    const db = await openDB();
    return reqToPromise(db.transaction(store, 'readonly').objectStore(store).getAll());
  }

  async function getOne(store, key) {
    const db = await openDB();
    return reqToPromise(db.transaction(store, 'readonly').objectStore(store).get(key));
  }

  async function put(store, obj) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(store, 'readwrite');
      const r = t.objectStore(store).put(obj);
      t.oncomplete = () => resolve(r.result);
      t.onerror = () => reject(t.error);
    });
  }

  async function del(store, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(store, 'readwrite');
      t.objectStore(store).delete(key);
      t.oncomplete = () => resolve(true);
      t.onerror = () => reject(t.error);
    });
  }

  async function clearStore(store) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(store, 'readwrite');
      t.objectStore(store).clear();
      t.oncomplete = () => resolve(true);
      t.onerror = () => reject(t.error);
    });
  }

  /* ===================== 初始化 ===================== */

  const DEFAULT_TYPES = [
    ['hour1', '1小时卡', 'hour', 1, 10], ['hour6', '6小时卡', 'hour', 6, 12],
    ['hour12', '12小时卡', 'hour', 12, 14], ['hour24', '24小时卡', 'hour', 24, 16],
    ['day', '天卡', 'day', 1, 20], ['week', '周卡', 'day', 7, 30],
    ['month', '月卡', 'day', 30, 40], ['quarter', '季卡', 'day', 90, 50],
    ['year', '年卡', 'day', 365, 60], ['credit', '额度卡', 'credit', 0, 110],
  ];

  const DEFAULT_SETTINGS = {
    site_name: '释然团队', card_prefix: '', bind_device: '1', sign_required: '1',
    heart_interval: '300', recharge_rate: '1', client_ver: '1.0.0', download_url: '',
    allow_rebind: '1', self_unbind: '1', agent_register_open: '1',
  };

  async function ensureInit() {
    const admins = await getAll('admins');
    if (admins.length === 0) {
      const salt = randHex(8);
      await put('admins', {
        username: 'admin',
        password_hash: await hashPassword('admin888', salt),
        salt,
        created_at: now(),
      });
    }

    const apps = await getAll('apps');
    if (apps.length === 0) {
      const t = now();
      const secret = randHex(24);
      await put('apps', {
        app_id: 'default', name: '释然团队', secret, version: '1.0.0',
        download_url: '', notice: '', enabled: 1, created_at: t,
      });
      for (const [code, name, unit, value, sort] of DEFAULT_TYPES) {
        await put('card_types', {
          app_id: 'default', code, name, unit, value,
          enabled: 1, sort, remark: '', created_at: t,
        });
      }
    }

    const settings = await getAll('settings');
    if (settings.length === 0) {
      for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
        await put('settings', { k, v });
      }
    }
  }

  async function getSetting(k, d) {
    const rows = await getAll('settings');
    const r = rows.find(x => x.k === k);
    return r ? r.v : d;
  }

  async function setSetting(k, v) {
    const rows = await getAll('settings');
    const r = rows.find(x => x.k === k);
    if (r) { r.v = String(v); await put('settings', r); }
    else await put('settings', { k, v: String(v) });
  }

  /* ===================== 会话（登录态） ===================== */

  const SESSION_KEY = 'shiran_session';

  function setSession(data) {
    localStorage.setItem(SESSION_KEY, JSON.stringify(data));
  }
  function getSession() {
    try { return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null'); }
    catch (e) { return null; }
  }
  function clearSession() { localStorage.removeItem(SESSION_KEY); }

  /* ===================== 业务逻辑 ===================== */

  async function generateCards(data) {
    const appId = data.app_id || 'default';
    const count = Math.max(1, Math.min(10000, parseInt(data.count, 10) || 1));
    const maxDevices = Math.max(1, Math.min(10, parseInt(data.max_devices, 10) || 1));
    const remark = data.remark || '';

    const apps = await getAll('apps');
    const app = apps.find(a => a.app_id === appId);
    if (!app) return { code: 3002, msg: '应用不存在：' + appId };

    const types = await getAll('card_types');
    const type = types.find(t => t.app_id === appId && t.code === data.type_code && t.enabled);
    if (!type) return { code: 3001, msg: '卡类型不存在或已禁用：' + data.type_code };

    let faceValue = type.value;
    const tv = data.type_value;
    if (tv !== null && tv !== undefined && tv !== '') {
      const v = parseInt(tv, 10);
      if (isNaN(v) || v <= 0) return { code: 1001, msg: '面值必须是大于 0 的整数' };
      if (v > 100000000) return { code: 1001, msg: '面值过大（上限 1 亿）' };
      faceValue = v;
    } else if (type.unit === 'credit' && !type.value) {
      return { code: 1001, msg: '生成' + type.name + '时必须填写额度数量' };
    }
    if (faceValue <= 0) return { code: 1001, msg: '面值必须大于 0' };

    const prefix = await getSetting('card_prefix', '');
    const t = now();
    const batch = 'B' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + randHex(2).toUpperCase();
    const keys = [];

    const existing = await getAll('cards');
    const usedKeys = new Set(existing.map(c => c.card_key));

    let tries = 0;
    while (keys.length < count && tries < count * 30) {
      tries++;
      const k = genCardKey(4, 4, prefix);
      if (usedKeys.has(k)) continue;
      usedKeys.add(k);
      await put('cards', {
        app_id: appId, card_key: k, type_code: type.code, type_name: type.name,
        unit: type.unit, value: faceValue,
        remain: type.unit === 'credit' ? faceValue : 0,
        status: 'unused', agent_id: null, batch_no: batch,
        max_devices: maxDevices, owner_device: null,
        activated_at: null, expire_at: null, used_count: 0,
        remark, created_at: t,
      });
      keys.push(k);
    }

    return {
      code: 0, msg: '成功生成 ' + keys.length + ' 张',
      batch, count: keys.length, cards: keys, app_id: appId,
      unit: type.unit, face_value: faceValue, type_name: type.name,
    };
  }

  function publicCard(card, user, devices) {
    const t = now();
    const isTime = card.unit === 'hour' || card.unit === 'day';
    return {
      card_key: card.card_key, app_id: card.app_id,
      type_code: card.type_code, type_name: card.type_name,
      unit: card.unit, value: card.value, status: card.status,
      activated_at: card.activated_at, expire_at: card.expire_at,
      remain_days: (isTime && card.expire_at) ? Math.max(0, Math.ceil((card.expire_at - t) / 86400000)) : null,
      remain_hours: (isTime && card.expire_at) ? Math.max(0, Math.ceil((card.expire_at - t) / 3600000)) : null,
      max_devices: card.max_devices, devices: devices || [],
      user: user ? {
        credit: user.credit, total_credit: user.total_credit, used_credit: user.used_credit,
        expire_at: user.expire_at,
        remain_days: user.expire_at ? Math.max(0, Math.ceil((user.expire_at - t) / 86400000)) : 0,
        remain_hours: user.expire_at ? Math.max(0, Math.ceil((user.expire_at - t) / 3600000)) : 0,
        is_vip: !!(user.expire_at && user.expire_at > t), ban: user.ban,
      } : null,
    };
  }

  async function activateCard(appId, cardKey, deviceId) {
    if (!cardKey) return { code: 1001, msg: '卡密不能为空' };
    const cards = await getAll('cards');
    const card = cards.find(c => c.card_key === cardKey);
    if (!card) return { code: 2001, msg: '卡密不存在' };
    if (card.app_id !== appId) return { code: 2001, msg: '该卡密不属于此应用' };
    if (card.status === 'disabled') return { code: 2004, msg: '卡密已被封禁' };
    if (card.status === 'expired') return { code: 2003, msg: '卡密已过期' };

    const t = now();
    const isTime = card.unit === 'hour' || card.unit === 'day';
    const msPerUnit = card.unit === 'hour' ? 3600000 : 86400000;

    if (card.status === 'used') return await verifyCard(appId, cardKey, deviceId);

    if (deviceId) {
      const devices = await getAll('card_devices');
      const bound = devices.filter(d => d.card_id === card.id);
      const maxDev = card.max_devices || 1;
      if (bound.length >= maxDev && !bound.some(d => d.device_id === deviceId)) {
        return { code: 2006, msg: '该卡已绑定 ' + bound.length + ' 台设备（上限 ' + maxDev + '），请先解绑' };
      }
    }

    let users = await getAll('users');
    let user = users.find(u => u.card_key === cardKey);
    if (!user) {
      await put('users', {
        card_key: cardKey, app_id: appId, credit: 0, total_credit: 0, used_credit: 0,
        expire_at: null, vip_level: 0, ban: 0, created_at: t, updated_at: t,
      });
      users = await getAll('users');
      user = users.find(u => u.card_key === cardKey);
    }

    let expireAt = card.expire_at;
    if (isTime) {
      const base = (user.expire_at && user.expire_at > t) ? user.expire_at : t;
      expireAt = base + card.value * msPerUnit;
      user.expire_at = expireAt;
      user.vip_level = (user.vip_level || 0) + 1;
      user.updated_at = t;
      await put('users', user);
    } else {
      const rate = parseFloat(await getSetting('recharge_rate', '1')) || 1;
      const add = Math.floor(card.value * rate);
      user.credit = (user.credit || 0) + add;
      user.total_credit = (user.total_credit || 0) + add;
      user.updated_at = t;
      await put('users', user);
      await put('credits_log', {
        card_key: cardKey, delta: add, balance: user.credit,
        source: 'card_activate', ref: cardKey,
        remark: '卡密激活 ' + card.type_name, ip: '', created_at: t,
      });
    }

    card.status = 'used';
    card.activated_at = t;
    card.expire_at = expireAt;
    card.used_count = (card.used_count || 0) + 1;
    if (deviceId) card.owner_device = card.owner_device || deviceId;
    if (card.unit === 'credit') card.remain = 0;
    await put('cards', card);

    if (deviceId) {
      await put('card_devices', {
        card_id: card.id, device_id: deviceId, first_seen: t, last_seen: t,
      });
    }

    const devices2 = (await getAll('card_devices')).filter(d => d.card_id === card.id);
    return { code: 0, msg: '激活成功', card: publicCard(card, user, devices2) };
  }

  async function verifyCard(appId, cardKey, deviceId, heartbeat) {
    if (!cardKey) return { code: 1001, msg: '卡密不能为空' };
    const cards = await getAll('cards');
    const card = cards.find(c => c.card_key === cardKey);
    if (!card) return { code: 2001, msg: '卡密不存在' };
    if (card.app_id !== appId) return { code: 2001, msg: '该卡密不属于此应用' };
    if (card.status === 'disabled') return { code: 2004, msg: '卡密已被封禁' };
    if (card.status === 'unused') return { code: 2005, msg: '卡密尚未激活，请先激活' };

    const t = now();
    const users = await getAll('users');
    const user = users.find(u => u.card_key === cardKey);
    if (!user) return { code: 2005, msg: '卡密数据异常，请重新激活' };
    if (user.ban) return { code: 2009, msg: '该账号已被封禁' };

    const isTime = card.unit === 'hour' || card.unit === 'day';
    if (isTime) {
      if (!user.expire_at || user.expire_at < t) {
        card.status = 'expired';
        await put('cards', card);
        return { code: 2003, msg: '卡密已过期，请续费' };
      }
    } else {
      if ((user.credit || 0) <= 0) return { code: 2008, msg: '额度已用完，请充值' };
    }

    if (deviceId) {
      const devices = await getAll('card_devices');
      const bound = devices.filter(d => d.card_id === card.id);
      const maxDev = card.max_devices || 1;
      if (bound.length === 0) {
        await put('card_devices', { card_id: card.id, device_id: deviceId, first_seen: t, last_seen: t });
        card.owner_device = deviceId;
        await put('cards', card);
      } else if (bound.some(d => d.device_id === deviceId)) {
        const d0 = bound.find(d => d.device_id === deviceId);
        d0.last_seen = t;
        await put('card_devices', d0);
      } else if (bound.length < maxDev) {
        await put('card_devices', { card_id: card.id, device_id: deviceId, first_seen: t, last_seen: t });
      } else {
        return {
          code: 2007,
          msg: '该卡已绑定其他设备（上限 ' + maxDev + ' 台），如需换机请解绑',
          bound_devices: bound.map(d => d.device_id),
        };
      }
    }

    const devices2 = (await getAll('card_devices')).filter(d => d.card_id === card.id);
    return {
      code: 0, msg: heartbeat ? '心跳正常' : '验证通过',
      card: publicCard(card, user, devices2), server_time: t,
    };
  }

  async function redeemCredit(appId, cardKey, targetKey, deviceId) {
    const cards = await getAll('cards');
    const card = cards.find(c => c.card_key === cardKey);
    if (!card) return { code: 2001, msg: '卡密不存在' };
    if (card.app_id !== appId) return { code: 2001, msg: '该卡密不属于此应用' };
    if (card.unit !== 'credit') return { code: 1001, msg: '只有额度卡可以充值' };
    if (card.status === 'disabled') return { code: 2004, msg: '卡密已被封禁' };
    if (card.status === 'used') return { code: 2002, msg: '该额度卡已被使用' };

    const t = now();
    const rate = parseFloat(await getSetting('recharge_rate', '1')) || 1;
    const add = Math.floor(card.value * rate);

    let users = await getAll('users');
    let user = users.find(u => u.card_key === targetKey);
    if (!user) {
      await put('users', {
        card_key: targetKey, app_id: appId, credit: 0, total_credit: 0, used_credit: 0,
        expire_at: null, vip_level: 0, ban: 0, created_at: t, updated_at: t,
      });
      users = await getAll('users');
      user = users.find(u => u.card_key === targetKey);
    }

    user.credit = (user.credit || 0) + add;
    user.total_credit = (user.total_credit || 0) + add;
    user.updated_at = t;
    await put('users', user);

    await put('credits_log', {
      card_key: targetKey, delta: add, balance: user.credit,
      source: 'card_redeem', ref: cardKey,
      remark: '额度充值 ' + card.type_name, ip: '', created_at: t,
    });

    card.status = 'used';
    card.activated_at = t;
    card.remain = 0;
    card.used_count = (card.used_count || 0) + 1;
    await put('cards', card);

    return { code: 0, msg: '充值成功，增加 ' + add + ' 额度', add, credit: user.credit, total_credit: user.total_credit };
  }

  async function consumeCredit(cardKey, amount, remark) {
    const users = await getAll('users');
    const user = users.find(u => u.card_key === cardKey);
    if (!user) return { code: 3003, msg: '卡密未激活' };
    if ((user.credit || 0) < amount) {
      return { code: 2008, msg: '额度不足，需要 ' + amount + '，当前 ' + (user.credit || 0) };
    }
    const t = now();
    user.credit -= amount;
    user.used_credit = (user.used_credit || 0) + amount;
    user.updated_at = t;
    await put('users', user);
    await put('credits_log', {
      card_key: cardKey, delta: -amount, balance: user.credit,
      source: 'consume', ref: remark || '', remark: remark || '业务消耗', ip: '', created_at: t,
    });
    return { code: 0, msg: '扣费成功', cost: amount, balance: user.credit };
  }

  /* ===================== 路由 ===================== */

  async function handleApi(path, method, body) {
    await ensureInit();

    /* ---------- 管理端登录 ---------- */
    if (path === '/api/admin/login' && method === 'POST') {
      const admins = await getAll('admins');
      const a = admins.find(x => x.username === body.username);
      if (!a) return { code: 4001, msg: '账号或密码错误' };
      const h = await hashPassword(body.password, a.salt);
      if (h !== a.password_hash) return { code: 4001, msg: '账号或密码错误' };
      setSession({ role: 'admin', username: a.username, ts: now() });
      return { code: 0, msg: '登录成功', token: 'local-session', username: a.username };
    }

    /* ---------- 管理端鉴权 ---------- */
    if (path.startsWith('/api/admin/')) {
      if (path === '/api/admin/init' || path === '/api/admin/status') {
        const admins = await getAll('admins');
        if (path === '/api/admin/status') return { code: 0, msg: 'ok', initialized: admins.length > 0 };
        return { code: 0, msg: '已初始化' };
      }
      const sess = getSession();
      if (!sess || sess.role !== 'admin') return { code: 4001, msg: '请先登录' };
      return await adminApi(path, method, body);
    }

    /* ---------- 客户端 ---------- */
    if (path.startsWith('/api/client/')) {
      const appId = body.app_id || 'default';

      if (path === '/api/client/config') {
        const apps = await getAll('apps');
        const app = apps.find(a => a.app_id === appId);
        const types = (await getAll('card_types')).filter(t => t.app_id === appId && t.enabled);
        return {
          code: 0, msg: 'ok', app_id: appId,
          app_name: app ? app.name : '',
          site_name: await getSetting('site_name', '释然团队'),
          bind_device: (await getSetting('bind_device', '1')) === '1',
          sign_required: false,
          heart_interval: parseInt(await getSetting('heart_interval', '300'), 10),
          client_ver: app ? app.version : '1.0.0',
          download_url: app ? (app.download_url || '') : '',
          types: types.map(t => ({ code: t.code, name: t.name, unit: t.unit, value: t.value })),
        };
      }
      if (path === '/api/client/time') return { code: 0, msg: 'ok', time: now() };
      if (path === '/api/client/activate') {
        return await activateCard(appId, body.card_key, body.device_id);
      }
      if (path === '/api/client/verify') {
        return await verifyCard(appId, body.card_key, body.device_id, false);
      }
      if (path === '/api/client/heartbeat') {
        return await verifyCard(appId, body.card_key, body.device_id, true);
      }
      if (path === '/api/client/redeem') {
        return await redeemCredit(appId, body.card_key, body.target_key || body.card_key, body.device_id);
      }
      if (path === '/api/client/consume') {
        return await consumeCredit(body.card_key, Math.max(1, parseInt(body.amount, 10) || 1), body.remark);
      }
      if (path === '/api/client/balance') {
        const users = await getAll('users');
        const u = users.find(x => x.card_key === body.card_key);
        if (!u) return { code: 3003, msg: '卡密未激活' };
        return {
          code: 0, msg: 'ok', credit: u.credit, total_credit: u.total_credit,
          used_credit: u.used_credit, expire_at: u.expire_at,
          is_vip: !!(u.expire_at && u.expire_at > now()),
          remain_hours: u.expire_at ? Math.max(0, Math.ceil((u.expire_at - now()) / 3600000)) : 0,
          remain_days: u.expire_at ? Math.max(0, Math.ceil((u.expire_at - now()) / 86400000)) : 0,
        };
      }
    }

    /* ---------- 网页端 ---------- */
    if (path.startsWith('/api/web/')) {
      const appId = body.app_id || 'default';
      if (path === '/api/web/activate') return await activateCard(appId, body.card_key, body.device_id);
      if (path === '/api/web/verify') return await verifyCard(appId, body.card_key, body.device_id, false);
      if (path === '/api/web/redeem') {
        return await redeemCredit(appId, body.card_key, body.target_key || body.card_key, body.device_id);
      }
      if (path === '/api/web/balance') {
        const users = await getAll('users');
        const u = users.find(x => x.card_key === body.card_key);
        if (!u) return { code: 3003, msg: '该卡密未激活或不存在' };
        return {
          code: 0, msg: 'ok', credit: u.credit, total_credit: u.total_credit,
          used_credit: u.used_credit, expire_at: u.expire_at,
          is_vip: !!(u.expire_at && u.expire_at > now()),
          remain_hours: u.expire_at ? Math.max(0, Math.ceil((u.expire_at - now()) / 3600000)) : 0,
          remain_days: u.expire_at ? Math.max(0, Math.ceil((u.expire_at - now()) / 86400000)) : 0,
        };
      }
      if (path === '/api/web/bindings') {
        const cards = await getAll('cards');
        const card = cards.find(c => c.card_key === body.card_key);
        if (!card) return { code: 2001, msg: '卡密不存在' };
        const devices = (await getAll('card_devices')).filter(d => d.card_id === card.id);
        const su = (await getSetting('self_unbind', '1')) !== '0';
        const ar = (await getSetting('allow_rebind', '1')) !== '0';
        return {
          code: 0, msg: 'ok', card_key: card.card_key, type_name: card.type_name,
          status: card.status, max_devices: card.max_devices, devices,
          self_unbind: su && ar,
        };
      }
      if (path === '/api/web/unbind') {
        const su = (await getSetting('self_unbind', '1')) !== '0';
        const ar = (await getSetting('allow_rebind', '1')) !== '0';
        if (!su || !ar) return { code: 4002, msg: '管理员已关闭自助解绑，请联系客服' };
        const cards = await getAll('cards');
        const card = cards.find(c => c.card_key === body.card_key);
        if (!card) return { code: 2001, msg: '卡密不存在' };
        const all = await getAll('card_devices');
        const targets = all.filter(d => d.card_id === card.id &&
          (!body.device_id || d.device_id === body.device_id));
        for (const d of targets) await del('card_devices', d.id);
        const left = (await getAll('card_devices')).filter(d => d.card_id === card.id).length;
        if (left === 0) { card.owner_device = null; await put('cards', card); }
        return { code: 0, msg: left === 0 ? '已全部解绑，可在新设备激活' : '已解绑，还剩 ' + left + ' 台', left };
      }
    }

    /* ---------- 代理端 ---------- */
    if (path.startsWith('/api/agent/')) {
      if (path === '/api/agent/login' && method === 'POST') {
        const agents = await getAll('agents');
        const a = agents.find(x => x.username === body.username);
        if (!a) return { code: 4001, msg: '账号或密码错误' };
        const h = await hashPassword(body.password, a.salt);
        if (h !== a.password_hash) return { code: 4001, msg: '账号或密码错误' };
        if (a.frozen) return { code: 4002, msg: '该代理已被冻结' };
        setSession({ role: 'agent', username: a.username, uid: a.id, ts: now() });
        return { code: 0, msg: '登录成功', token: 'local-session', username: a.username };
      }
      if (path === '/api/agent/register' && method === 'POST') {
        const open = await getSetting('agent_register_open', '1');
        if (open === '0') return { code: 4002, msg: '管理员已关闭代理注册' };
        const agents = await getAll('agents');
        if (agents.find(x => x.username === body.username)) return { code: 1001, msg: '账号已存在' };
        const salt = randHex(8);
        const apiKey = 'AK' + randHex(16).toUpperCase();
        let parentId = null;
        if (body.parent) {
          const pa = agents.find(x => x.username === body.parent);
          if (pa) parentId = pa.id;
        }
        await put('agents', {
          username: body.username, password_hash: await hashPassword(body.password, salt), salt,
          nickname: body.nickname || body.username, contact: body.contact || '',
          parent_id: parentId, level: 1, balance: 0, frozen: 0,
          api_key: apiKey, created_at: now(),
        });
        return { code: 0, msg: '注册成功，请登录代理后台', username: body.username, api_key: apiKey };
      }

      const sess = getSession();
      if (!sess || sess.role !== 'agent') return { code: 4001, msg: '请先登录' };
      const agents = await getAll('agents');
      const agent = agents.find(a => a.id === sess.uid);
      if (!agent) return { code: 4001, msg: '代理不存在' };

      if (path === '/api/agent/me') {
        const cards = (await getAll('cards')).filter(c => c.agent_id === agent.id);
        const childCount = agents.filter(a => a.parent_id === agent.id).length;
        const types = (await getAll('card_types')).filter(t => t.enabled);
        return {
          code: 0, msg: 'ok',
          agent: {
            id: agent.id, username: agent.username, nickname: agent.nickname,
            contact: agent.contact, level: agent.level, balance: agent.balance,
            api_key: agent.api_key, parent_id: agent.parent_id,
          },
          stats: {
            card_total: cards.length,
            card_unused: cards.filter(c => c.status === 'unused').length,
            card_used: cards.filter(c => c.status === 'used').length,
            child_count: childCount,
          },
          types: types.map(t => ({ code: t.code, name: t.name, unit: t.unit, value: t.value })),
        };
      }
      if (path === '/api/agent/cards/generate') {
        return await generateCards({ ...body, agent_id: agent.id });
      }
      if (path === '/api/agent/cards') {
        const cards = (await getAll('cards')).filter(c => c.agent_id === agent.id).slice(0, 200);
        return { code: 0, msg: 'ok', list: cards };
      }
      if (path === '/api/agent/logs') {
        const logs = (await getAll('agent_logs')).filter(l => l.agent_id === agent.id).slice(-100).reverse();
        return { code: 0, msg: 'ok', list: logs };
      }
      if (path === '/api/agent/withdrawals') {
        const ws = (await getAll('withdrawals')).filter(w => w.agent_id === agent.id).reverse();
        return { code: 0, msg: 'ok', list: ws };
      }
      if (path === '/api/agent/withdraw') {
        const amount = parseFloat(body.amount) || 0;
        if (amount <= 0) return { code: 1001, msg: '提现金额必须大于 0' };
        if (agent.balance < amount) return { code: 1001, msg: '余额不足，当前 ¥' + agent.balance.toFixed(2) };
        agent.balance = +(agent.balance - amount).toFixed(2);
        await put('agents', agent);
        await put('withdrawals', {
          agent_id: agent.id, amount, status: 'pending',
          account: body.account || '', remark: body.remark || '', created_at: now(),
        });
        await put('agent_logs', {
          agent_id: agent.id, delta: -amount, balance: agent.balance,
          type: 'withdraw', remark: '提现申请', created_at: now(),
        });
        return { code: 0, msg: '提现申请已提交，等待审核', balance: agent.balance };
      }
    }

    return { code: 404, msg: '接口不存在：' + path };
  }

  /* ===================== 管理端具体接口 ===================== */

  async function adminApi(path, method, body) {
    const sub = path.replace('/api/admin/', '');

    if (sub === 'me') return { code: 0, msg: 'ok', username: getSession().username, role: 'admin' };

    if (sub === 'stats') {
      const cards = await getAll('cards');
      const agents = await getAll('agents');
      const users = await getAll('users');
      const logs = await getAll('verify_logs');
      const apps = await getAll('apps');
      const todayStart = new Date().setHours(0, 0, 0, 0);

      const trend = [];
      for (let i = 6; i >= 0; i--) {
        const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
        const s = d.getTime(), e = s + 86400000;
        trend.push({
          date: (d.getMonth() + 1) + '/' + d.getDate(),
          count: logs.filter(l => l.created_at >= s && l.created_at < e).length,
        });
      }

      return {
        code: 0, msg: 'ok',
        cards_total: cards.length,
        cards_unused: cards.filter(c => c.status === 'unused').length,
        cards_used: cards.filter(c => c.status === 'used').length,
        cards_today: cards.filter(c => c.created_at >= todayStart).length,
        agents_total: agents.length, users_total: users.length,
        logs_today: logs.filter(l => l.created_at >= todayStart).length,
        apps_total: apps.length, trend,
        app_stats: apps.map(a => ({
          app_id: a.app_id, name: a.name,
          cnt: cards.filter(c => c.app_id === a.app_id).length,
        })),
      };
    }

    if (sub === 'apps') {
      if (method === 'GET') return { code: 0, msg: 'ok', list: await getAll('apps') };
      if (method === 'POST') {
        const apps = await getAll('apps');
        if (apps.find(a => a.app_id === body.app_id)) return { code: 1001, msg: '该 app_id 已存在' };
        const secret = randHex(24);
        const t = now();
        await put('apps', {
          app_id: body.app_id, name: body.name, secret, version: '1.0.0',
          download_url: '', notice: '', enabled: 1, created_at: t,
        });
        for (const [code, name, unit, value, sort] of DEFAULT_TYPES) {
          await put('card_types', {
            app_id: body.app_id, code, name, unit, value,
            enabled: 1, sort, remark: '', created_at: t,
          });
        }
        return { code: 0, msg: '应用创建成功', app_id: body.app_id, secret };
      }
    }

    if (sub.startsWith('apps/')) {
      const appId = sub.split('/')[1];
      const apps = await getAll('apps');
      const app = apps.find(a => a.app_id === appId);
      if (!app) return { code: 3002, msg: '应用不存在' };

      if (method === 'POST') {
        if (body.action === 'reset_secret') {
          app.secret = randHex(24);
          await put('apps', app);
          return { code: 0, msg: '密钥已重置', secret: app.secret };
        }
        app.name = body.name || app.name;
        app.version = body.version || app.version;
        app.download_url = body.download_url !== undefined ? body.download_url : app.download_url;
        app.notice = body.notice !== undefined ? body.notice : app.notice;
        if (body.enabled !== undefined) app.enabled = body.enabled ? 1 : 0;
        await put('apps', app);
        return { code: 0, msg: '已更新' };
      }
      if (method === 'DELETE') {
        if (appId === 'default') return { code: 1001, msg: '默认应用不能删除' };
        await del('apps', app.id);
        return { code: 0, msg: '已删除' };
      }
    }

    if (sub === 'types') {
      if (method === 'GET') {
        const appId = body.app_id || 'default';
        const list = (await getAll('card_types'))
          .filter(t => t.app_id === appId)
          .sort((a, b) => (a.unit > b.unit ? 1 : -1) || (a.sort - b.sort));
        return { code: 0, msg: 'ok', list };
      }
      if (method === 'POST') {
        const appId = body.app_id || 'default';
        const types = await getAll('card_types');
        if (types.find(t => t.app_id === appId && t.code === body.code)) {
          return { code: 1001, msg: '类型代码已存在' };
        }
        const en = (body.enabled === undefined || body.enabled === null) ? 1 : (body.enabled ? 1 : 0);
        await put('card_types', {
          app_id: appId, code: body.code, name: body.name, unit: body.unit,
          value: parseInt(body.value, 10) || 0, enabled: en,
          sort: parseInt(body.sort, 10) || 100, remark: body.remark || '', created_at: now(),
        });
        return { code: 0, msg: '添加成功' };
      }
    }

    if (sub.startsWith('types/')) {
      const id = parseInt(sub.split('/')[1], 10);
      const types = await getAll('card_types');
      const t = types.find(x => x.id === id);
      if (!t) return { code: 404, msg: '类型不存在' };
      if (method === 'PUT') {
        t.name = body.name || t.name;
        t.unit = body.unit || t.unit;
        if (body.value !== undefined) t.value = parseInt(body.value, 10) || 0;
        if (body.enabled !== undefined) t.enabled = body.enabled ? 1 : 0;
        if (body.sort !== undefined) t.sort = parseInt(body.sort, 10) || 100;
        if (body.remark !== undefined) t.remark = body.remark;
        await put('card_types', t);
        return { code: 0, msg: '已更新' };
      }
      if (method === 'DELETE') {
        await del('card_types', id);
        return { code: 0, msg: '已删除' };
      }
    }

    if (sub === 'cards' && method === 'GET') {
      const page = Math.max(1, parseInt(body.page, 10) || 1);
      const size = Math.min(500, parseInt(body.size, 10) || 20);
      let list = await getAll('cards');
      const apps = await getAll('apps');

      if (body.kw) {
        const k = body.kw.toLowerCase();
        list = list.filter(c => (c.card_key || '').toLowerCase().includes(k)
          || (c.owner_device || '').toLowerCase().includes(k)
          || (c.remark || '').toLowerCase().includes(k));
      }
      if (body.status) list = list.filter(c => c.status === body.status);
      if (body.type) list = list.filter(c => c.type_code === body.type);
      if (body.batch) list = list.filter(c => c.batch_no === body.batch);
      if (body.app_id) list = list.filter(c => c.app_id === body.app_id);
      if (body.unit) list = list.filter(c => c.unit === body.unit);
      if (body.exclude_unit) {
        const ex = String(body.exclude_unit).split(',').filter(Boolean);
        if (ex.length) list = list.filter(c => !ex.includes(c.unit));
      }

      list.sort((a, b) => b.id - a.id);
      const total = list.length;
      const pageList = list.slice((page - 1) * size, page * size).map(c => {
        const app = apps.find(a => a.app_id === c.app_id);
        return { ...c, app_name: app ? app.name : c.app_id };
      });
      return { code: 0, msg: 'ok', total, page, size, list: pageList };
    }

    if (sub === 'cards/generate' && method === 'POST') return await generateCards(body);

    if (sub.match(/^cards\/(\d+)\/(disable|unbind|extend|reset)$/)) {
      const m = sub.match(/^cards\/(\d+)\/(disable|unbind|extend|reset)$/);
      const id = parseInt(m[1], 10);
      const act = m[2];
      const cards = await getAll('cards');
      const card = cards.find(c => c.id === id);
      if (!card) return { code: 2001, msg: '卡密不存在' };
      const t = now();

      if (act === 'disable') {
        card.status = card.status === 'disabled' ? (card.activated_at ? 'used' : 'unused') : 'disabled';
        await put('cards', card);
        return { code: 0, msg: card.status === 'disabled' ? '已封禁' : '已解封' };
      }
      if (act === 'unbind') {
        const devs = (await getAll('card_devices')).filter(d => d.card_id === id);
        for (const d of devs) await del('card_devices', d.id);
        card.owner_device = null;
        await put('cards', card);
        return { code: 0, msg: '已解绑，可在新设备激活' };
      }
      if (act === 'extend') {
        const days = parseInt(body.days, 10) || 30;
        const users = await getAll('users');
        const u = users.find(x => x.card_key === card.card_key);
        if (!u) return { code: 3003, msg: '该卡未激活，无到期时间' };
        const base = (u.expire_at && u.expire_at > t) ? u.expire_at : t;
        u.expire_at = base + days * 86400000;
        u.updated_at = t;
        await put('users', u);
        card.expire_at = u.expire_at;
        await put('cards', card);
        return { code: 0, msg: '已延长 ' + days + ' 天' };
      }
      if (act === 'reset') {
        card.status = 'unused';
        card.activated_at = null;
        card.expire_at = null;
        card.owner_device = null;
        card.used_count = 0;
        card.remain = card.unit === 'credit' ? card.value : 0;
        await put('cards', card);
        const devs = (await getAll('card_devices')).filter(d => d.card_id === id);
        for (const d of devs) await del('card_devices', d.id);
        const users = await getAll('users');
        const u = users.find(x => x.card_key === card.card_key);
        if (u) await del('users', u.id);
        return { code: 0, msg: '已重置为未使用' };
      }
    }

    if (sub.match(/^cards\/\d+$/) && method === 'DELETE') {
      const id = parseInt(sub.split('/')[1], 10);
      const devs = (await getAll('card_devices')).filter(d => d.card_id === id);
      for (const d of devs) await del('card_devices', d.id);
      await del('cards', id);
      return { code: 0, msg: '已删除' };
    }

    if (sub === 'cards/disable-batch' && method === 'POST') {
      const cards = await getAll('cards');
      const targets = cards.filter(c => c.batch_no === body.batch_no && c.status === 'unused');
      for (const c of targets) { c.status = 'disabled'; await put('cards', c); }
      return { code: 0, msg: '批次已封禁', affected: targets.length };
    }

    if (sub === 'cards/export') {
      let list = await getAll('cards');
      if (body.batch) list = list.filter(c => c.batch_no === body.batch);
      if (body.status) list = list.filter(c => c.status === body.status);
      if (body.app_id) list = list.filter(c => c.app_id === body.app_id);
      return { code: 0, msg: 'ok', text: list.map(c => c.card_key).join('\n') };
    }

    if (sub === 'users' && method === 'GET') {
      const page = Math.max(1, parseInt(body.page, 10) || 1);
      const size = Math.min(200, parseInt(body.size, 10) || 20);
      let list = await getAll('users');
      if (body.kw) list = list.filter(u => (u.card_key || '').includes(body.kw));
      list.sort((a, b) => b.updated_at - a.updated_at);
      return { code: 0, msg: 'ok', total: list.length, page, size, list: list.slice((page - 1) * size, page * size) };
    }

    if (sub === 'credits-log') {
      const list = (await getAll('credits_log')).sort((a, b) => b.id - a.id).slice(0, 200);
      return { code: 0, msg: 'ok', list };
    }

    if (sub === 'agents') {
      if (method === 'GET') {
        const agents = await getAll('agents');
        const cards = await getAll('cards');
        return {
          code: 0, msg: 'ok',
          list: agents.map(a => ({
            ...a,
            card_count: cards.filter(c => c.agent_id === a.id).length,
            child_count: agents.filter(x => x.parent_id === a.id).length,
          })),
        };
      }
      if (method === 'POST') {
        const agents = await getAll('agents');
        if (agents.find(a => a.username === body.username)) return { code: 1001, msg: '账号已存在' };
        const salt = randHex(8);
        const apiKey = 'AK' + randHex(16).toUpperCase();
        await put('agents', {
          username: body.username, password_hash: await hashPassword(body.password, salt), salt,
          nickname: body.nickname || '', contact: body.contact || '',
          parent_id: body.parent_id || null, level: parseInt(body.level, 10) || 1,
          balance: parseFloat(body.balance) || 0, frozen: 0, api_key: apiKey, created_at: now(),
        });
        return { code: 0, msg: '代理创建成功', api_key: apiKey };
      }
    }

    if (sub.match(/^agents\/\d+$/)) {
      const id = parseInt(sub.split('/')[1], 10);
      const agents = await getAll('agents');
      const a = agents.find(x => x.id === id);
      if (!a) return { code: 404, msg: '代理不存在' };
      if (method === 'PUT') {
        a.nickname = body.nickname !== undefined ? body.nickname : a.nickname;
        a.contact = body.contact !== undefined ? body.contact : a.contact;
        if (body.level !== undefined) a.level = parseInt(body.level, 10) || 1;
        if (body.frozen !== undefined) a.frozen = body.frozen ? 1 : 0;
        await put('agents', a);
        return { code: 0, msg: '已更新' };
      }
      if (method === 'DELETE') { await del('agents', id); return { code: 0, msg: '已删除' }; }
    }

    if (sub.match(/^agents\/\d+\/balance$/)) {
      const id = parseInt(sub.split('/')[2], 10);
      const agents = await getAll('agents');
      const a = agents.find(x => x.id === id);
      if (!a) return { code: 404, msg: '代理不存在' };
      const delta = parseFloat(body.delta) || 0;
      a.balance = +(a.balance + delta).toFixed(2);
      await put('agents', a);
      await put('agent_logs', {
        agent_id: id, delta, balance: a.balance, type: 'adjust',
        remark: body.remark || '管理员调整', created_at: now(),
      });
      return { code: 0, msg: '余额已调整', balance: a.balance };
    }

    if (sub.match(/^agents\/\d+\/resetpwd$/)) {
      const id = parseInt(sub.split('/')[2], 10);
      if (!body.password || body.password.length < 6) return { code: 1001, msg: '密码至少 6 位' };
      const agents = await getAll('agents');
      const a = agents.find(x => x.id === id);
      if (!a) return { code: 404, msg: '代理不存在' };
      a.salt = randHex(8);
      a.password_hash = await hashPassword(body.password, a.salt);
      await put('agents', a);
      return { code: 0, msg: '密码已重置' };
    }

    if (sub.match(/^agents\/\d+\/logs$/)) {
      const id = parseInt(sub.split('/')[1], 10);
      const list = (await getAll('agent_logs')).filter(l => l.agent_id === id).reverse().slice(0, 100);
      return { code: 0, msg: 'ok', list };
    }

    if (sub === 'withdrawals') {
      const ws = (await getAll('withdrawals')).sort((a, b) => b.id - a.id);
      const agents = await getAll('agents');
      return {
        code: 0, msg: 'ok',
        list: ws.map(w => {
          const a = agents.find(x => x.id === w.agent_id);
          return { ...w, username: a ? a.username : '#' + w.agent_id };
        }),
      };
    }

    if (sub.match(/^withdrawals\/\d+\/(approve|reject)$/)) {
      const m = sub.match(/^withdrawals\/(\d+)\/(approve|reject)$/);
      const id = parseInt(m[1], 10);
      const act = m[2];
      const ws = await getAll('withdrawals');
      const w = ws.find(x => x.id === id);
      if (!w) return { code: 404, msg: '提现申请不存在' };
      if (w.status !== 'pending') return { code: 1001, msg: '该申请已处理' };
      const t = now();
      if (act === 'approve') {
        w.status = 'approved'; w.processed_at = t;
        await put('withdrawals', w);
        return { code: 0, msg: '已通过' };
      } else {
        const agents = await getAll('agents');
        const a = agents.find(x => x.id === w.agent_id);
        if (a) {
          a.balance = +(a.balance + w.amount).toFixed(2);
          await put('agents', a);
          await put('agent_logs', {
            agent_id: w.agent_id, delta: w.amount, balance: a.balance,
            type: 'withdraw_reject', remark: '提现驳回退回', created_at: t,
          });
        }
        w.status = 'rejected'; w.processed_at = t;
        await put('withdrawals', w);
        return { code: 0, msg: '已驳回，余额已退回' };
      }
    }

    if (sub === 'logs') {
      let list = (await getAll('verify_logs')).sort((a, b) => b.id - a.id);
      if (body.kw) {
        list = list.filter(l => (l.card_key || '').includes(body.kw) || (l.device_id || '').includes(body.kw));
      }
      if (body.ok !== undefined && body.ok !== '') {
        list = list.filter(l => l.ok === (body.ok === '1' || body.ok === 1 ? 1 : 0));
      }
      return { code: 0, msg: 'ok', list: list.slice(0, 200) };
    }

    if (sub === 'notices') {
      if (method === 'GET') {
        const list = (await getAll('notices')).sort((a, b) => b.id - a.id);
        return { code: 0, msg: 'ok', list };
      }
      if (method === 'POST') {
        await put('notices', {
          title: body.title, content: body.content || '', ver: body.ver || '1.0.0',
          force: body.force ? 1 : 0, enabled: 1, created_at: now(),
        });
        return { code: 0, msg: '公告已发布' };
      }
    }

    if (sub.match(/^notices\/\d+$/) && method === 'DELETE') {
      await del('notices', parseInt(sub.split('/')[1], 10));
      return { code: 0, msg: '已删除' };
    }

    if (sub === 'settings') {
      if (method === 'GET') {
        const rows = await getAll('settings');
        const obj = {};
        for (const r of rows) obj[r.k] = r.v;
        return { code: 0, msg: 'ok', settings: obj };
      }
      if (method === 'POST') {
        const allow = ['site_name', 'card_prefix', 'bind_device', 'sign_required', 'heart_interval',
          'recharge_rate', 'client_ver', 'download_url', 'allow_rebind', 'notice', 'self_unbind',
          'agent_register_open'];
        for (const k of allow) {
          if (body[k] !== undefined) await setSetting(k, body[k]);
        }
        return { code: 0, msg: '设置已保存' };
      }
    }

    if (sub === 'backup') {
      const out = { exported_at: now(), version: '1.0.0-local' };
      for (const s of STORES) out[s] = await getAll(s);
      return { code: 0, msg: 'ok', data: out };
    }

    return { code: 404, msg: '管理接口不存在：' + sub };
  }

  /* ===================== 拦截 fetch ===================== */

  const origFetch = window.fetch.bind(window);

  window.fetch = async function (input, init) {
    let url, opts;
    if (typeof input === 'string') { url = input; opts = init || {}; }
    else if (input instanceof Request) { url = input.url; opts = { method: input.method }; }
    else { url = String(input); opts = init || {}; }

    // 只拦截同源的 /api/ 请求
    let pathname;
    try {
      const u = new URL(url, location.origin);
      if (u.origin !== location.origin) return origFetch(input, init);
      pathname = u.pathname;
    } catch (e) {
      return origFetch(input, init);
    }

    if (!pathname.startsWith('/api/')) return origFetch(input, init);

    // 解析 body
    let body = {};
    const method = (opts.method || 'GET').toUpperCase();
    if (opts.body) {
      try {
        body = typeof opts.body === 'string' ? JSON.parse(opts.body) : opts.body;
      } catch (e) { body = {}; }
    }

    // 把 query 参数也放进 body
    try {
      const u = new URL(url, location.origin);
      for (const [k, v] of u.searchParams) {
        if (body[k] === undefined) body[k] = v;
      }
    } catch (e) {}

    try {
      const result = await handleApi(pathname, method, body);

      // 记录日志
      if (pathname.includes('/client/') || pathname.includes('/web/')) {
        try {
          await put('verify_logs', {
            app_id: body.app_id || 'default',
            card_key: body.card_key || '',
            device_id: body.device_id || '',
            ip: 'local',
            action: pathname.split('/').pop(),
            ok: result.code === 0 ? 1 : 0,
            code: result.code || 0,
            msg: result.msg || '',
            created_at: now(),
          });
        } catch (e) {}
      }

      return new Response(JSON.stringify(result), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    } catch (e) {
      console.error('[local] API 错误:', pathname, e);
      return new Response(JSON.stringify({ code: 5000, msg: '本地处理错误：' + e.message }), {
        status: 200,
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
      });
    }
  };

  /* ===================== 暴露工具 ===================== */

  window.SHIRAN = {
    clearSession,
    getSession,
    exportAll: async () => {
      const out = {};
      for (const s of STORES) out[s] = await getAll(s);
      return out;
    },
    importAll: async (data) => {
      for (const s of STORES) {
        if (!data[s]) continue;
        await clearStore(s);
        for (const row of data[s]) await put(s, row);
      }
    },
    reset: async () => {
      for (const s of STORES) await clearStore(s);
      await ensureInit();
    },
  };

  // 启动时初始化
  ensureInit().then(() => {
    console.log('[释然团队] 本地数据库已就绪');
  }).catch(e => {
    console.error('[释然团队] 初始化失败:', e);
  });

})();
