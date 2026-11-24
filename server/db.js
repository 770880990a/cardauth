'use strict';
/**
 * 数据层 —— SQLite
 * 本地运行：数据放 ./data/cardauth.db
 * 云端运行：通过环境变量 DB_PATH 指定（挂载持久磁盘，例如 /data/cardauth.db）
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sqlite = require('./sqlite');

const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : (typeof process.pkg !== 'undefined'
      // 打包成 EXE 时：数据放在 exe 同级的 data 目录，方便备份和迁移
      ? path.join(path.dirname(process.execPath), 'data', 'cardauth.db')
      : path.join(__dirname, '..', 'data', 'cardauth.db'));

const DATA_DIR = path.dirname(DB_PATH);
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = sqlite.open(DB_PATH);

db.exec(`
-- ============ 管理员 ============
CREATE TABLE IF NOT EXISTS admins (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  last_login    INTEGER
);

-- ============ 应用（多应用管理：一个后台管多个软件） ============
CREATE TABLE IF NOT EXISTS apps (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id      TEXT UNIQUE NOT NULL,        -- 应用标识，客户端对接时传这个
  name        TEXT NOT NULL,               -- 应用名称
  secret      TEXT NOT NULL,               -- 该应用独立的通信密钥
  version     TEXT NOT NULL DEFAULT '1.0.0', -- 客户端最新版本号
  download_url TEXT,                       -- 客户端下载地址
  notice      TEXT,                        -- 公告
  enabled     INTEGER NOT NULL DEFAULT 1,
  remark      TEXT,
  created_at  INTEGER NOT NULL
);

-- ============ 卡类型（属于某个应用） ============
-- unit: day(时长卡，天/周/月) | credit(额度卡，充值额度) | count(次数卡)
CREATE TABLE IF NOT EXISTS card_types (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id      TEXT NOT NULL DEFAULT 'default',
  code        TEXT NOT NULL,               -- 同一应用内唯一
  name        TEXT NOT NULL,
  unit        TEXT NOT NULL,
  value       INTEGER NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  sort        INTEGER NOT NULL DEFAULT 100,
  remark      TEXT,
  created_at  INTEGER NOT NULL
);
-- 注意：依赖 app_id 的唯一索引在下方迁移逻辑之后创建
-- （老库此时还没有 app_id 列，直接在这里建会报错）

-- ============ 代理 ============
CREATE TABLE IF NOT EXISTS agents (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  nickname      TEXT,
  contact       TEXT,
  parent_id     INTEGER,
  level         INTEGER NOT NULL DEFAULT 1,
  balance       REAL NOT NULL DEFAULT 0,
  frozen        INTEGER NOT NULL DEFAULT 0,
  api_key       TEXT UNIQUE,
  created_at    INTEGER NOT NULL,
  FOREIGN KEY(parent_id) REFERENCES agents(id)
);

-- ============ 卡密 ============
CREATE TABLE IF NOT EXISTS cards (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  app_id       TEXT NOT NULL DEFAULT 'default',
  card_key     TEXT UNIQUE NOT NULL,
  type_code    TEXT NOT NULL,
  type_name    TEXT NOT NULL,
  unit         TEXT NOT NULL,
  value        INTEGER NOT NULL,
  remain       INTEGER NOT NULL DEFAULT 0,
  status       TEXT NOT NULL DEFAULT 'unused',
  agent_id     INTEGER,
  batch_no     TEXT,
  owner_device TEXT,
  activated_at INTEGER,
  expire_at    INTEGER,
  used_count   INTEGER NOT NULL DEFAULT 0,
  max_devices  INTEGER NOT NULL DEFAULT 1,
  remark       TEXT,
  created_at   INTEGER NOT NULL,
  FOREIGN KEY(agent_id) REFERENCES agents(id)
);
CREATE INDEX IF NOT EXISTS idx_cards_key ON cards(card_key);
CREATE INDEX IF NOT EXISTS idx_cards_agent ON cards(agent_id);
CREATE INDEX IF NOT EXISTS idx_cards_batch ON cards(batch_no);
CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status);

-- ============ 卡密绑定设备 ============
CREATE TABLE IF NOT EXISTS card_devices (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  card_id     INTEGER NOT NULL,
  device_id   TEXT NOT NULL,
  ip          TEXT,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  UNIQUE(card_id, device_id),
  FOREIGN KEY(card_id) REFERENCES cards(id) ON DELETE CASCADE
);

-- ============ 用户（额度账户，以卡密为主键） ============
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  card_key      TEXT UNIQUE NOT NULL,
  credit        INTEGER NOT NULL DEFAULT 0,
  total_credit  INTEGER NOT NULL DEFAULT 0,
  used_credit   INTEGER NOT NULL DEFAULT 0,
  expire_at     INTEGER,
  vip_level     INTEGER NOT NULL DEFAULT 0,
  ban           INTEGER NOT NULL DEFAULT 0,
  remark        TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

-- ============ 额度流水 ============
CREATE TABLE IF NOT EXISTS credits_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  card_key    TEXT NOT NULL,
  delta       INTEGER NOT NULL,
  balance     INTEGER NOT NULL,
  source      TEXT NOT NULL,
  ref         TEXT,
  remark      TEXT,
  ip          TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credits_log_key ON credits_log(card_key);

-- ============ 验证日志 ============
CREATE TABLE IF NOT EXISTS verify_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  card_key   TEXT,
  device_id  TEXT,
  ip         TEXT,
  action     TEXT,
  ok         INTEGER NOT NULL,
  code       INTEGER,
  msg        TEXT,
  raw        TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verify_logs_time ON verify_logs(created_at);

-- ============ 代理流水 ============
CREATE TABLE IF NOT EXISTS agent_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id   INTEGER NOT NULL,
  delta      REAL NOT NULL,
  balance    REAL NOT NULL,
  type       TEXT NOT NULL,
  ref        TEXT,
  remark     TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_logs_agent ON agent_logs(agent_id);

-- ============ 提现申请 ============
CREATE TABLE IF NOT EXISTS withdrawals (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id   INTEGER NOT NULL,
  amount     REAL NOT NULL,
  account    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'pending',
  remark     TEXT,
  created_at INTEGER NOT NULL,
  handled_at INTEGER
);

-- ============ 系统配置 ============
CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

-- ============ 公告/版本 ============
CREATE TABLE IF NOT EXISTS notices (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  title      TEXT NOT NULL,
  content    TEXT,
  ver        TEXT,
  force      INTEGER NOT NULL DEFAULT 0,
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

-- ============ 客户端离线授权令牌（可选） ============
CREATE TABLE IF NOT EXISTS tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  card_key   TEXT NOT NULL,
  device_id  TEXT NOT NULL,
  token      TEXT UNIQUE NOT NULL,
  issued_at  INTEGER NOT NULL,
  expire_at  INTEGER NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tokens_key ON tokens(card_key);
`);

const now = () => Date.now();

function hashPassword(pwd, salt) {
  return crypto.createHash('sha256').update(pwd + salt).digest('hex');
}

function getSetting(k, def = null) {
  const r = db.prepare('SELECT v FROM settings WHERE k=?').get(k);
  return r ? r.v : def;
}

function setSetting(k, v) {
  db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')
    .run(k, String(v));
}

function init() {
  const t = now();

  /* ---------- 老库迁移：补齐新增字段 ---------- */
  function tableCols(table) {
    try { return db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name); }
    catch (e) { return []; }
  }
  function addCol(table, col, ddl) {
    const cols = tableCols(table);
    if (cols.length && !cols.includes(col)) {
      try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`); } catch (e) {}
    }
  }
  addCol('cards', 'app_id', "app_id TEXT NOT NULL DEFAULT 'default'");
  addCol('card_types', 'app_id', "app_id TEXT NOT NULL DEFAULT 'default'");

  /* ---------- 清理已废弃的「次数卡」类型 ---------- */
  // 次数卡已合并进额度卡概念，删除没有卡密关联的次数卡类型
  try {
    db.prepare(`DELETE FROM card_types WHERE unit='count'
      AND NOT EXISTS (SELECT 1 FROM cards c WHERE c.type_code = card_types.code)`).run();
  } catch (e) {}

  /* ---------- 迁移完成后再建依赖 app_id 的索引 ---------- */
  try {
    // 老库里同一 code 可能重复（不分应用），先清理重复再去重
    const dups = db.prepare(`
      SELECT code, COUNT(*) c FROM card_types GROUP BY app_id, code HAVING c > 1`).all();
    for (const d of dups) {
      // 保留 id 最小的那条，其余改名为 code_dup_<id>
      const rows = db.prepare(
        'SELECT id FROM card_types WHERE code=? ORDER BY id').all(d.code);
      for (let i = 1; i < rows.length; i++) {
        try {
          db.prepare('UPDATE card_types SET code=? WHERE id=?')
            .run(d.code + '_dup' + rows[i].id, rows[i].id);
        } catch (e) {}
      }
    }
  } catch (e) {}
  try {
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_types_app_code ON card_types(app_id, code)');
  } catch (e) {
    console.error('[init] 卡类型唯一索引创建失败（可忽略）:', e.message);
  }

  /* ---------- 默认应用 ---------- */
  if (!db.prepare('SELECT COUNT(*) c FROM apps').get().c) {
    db.prepare(`INSERT INTO apps(app_id,name,secret,version,enabled,remark,created_at)
      VALUES(?,?,?,?,1,?,?)`)
      .run('default', '默认应用',
        process.env.API_SECRET || crypto.randomBytes(24).toString('hex'),
        '1.0.0', '系统创建，可改名或新增其它应用', t);
    console.log('[init] 已创建默认应用 (app_id=default)');
  }

  /* ---------- 默认卡类型（时长卡 / 额度卡 两大类） ---------- */
  // value 的含义：
  //   时长卡 unit='hour'  → value = 小时数（固定）
  //   时长卡 unit='day'   → value = 天数（固定）
  //   额度卡 unit='credit'→ value = 0 表示「面值不固定，生成时手动填」
  const defTypes = [
    // 时长卡（小时）
    ['hour1', '1小时卡', 'hour', 1, 5, '1小时时长'],
    ['hour6', '6小时卡', 'hour', 6, 6, '6小时时长'],
    ['hour12', '12小时卡', 'hour', 12, 7, '12小时时长'],
    ['hour24', '24小时卡', 'hour', 24, 8, '24小时时长'],
    // 时长卡（天及以上）
    ['day', '天卡', 'day', 1, 20, '1天时长'],
    ['week', '周卡', 'day', 7, 30, '7天时长'],
    ['month', '月卡', 'day', 30, 40, '30天时长'],
    ['quarter', '季卡', 'day', 90, 50, '90天时长'],
    ['year', '年卡', 'day', 365, 60, '365天时长'],
    // 额度卡（面值不固定，生成时手填额度）
    ['credit', '额度卡', 'credit', 0, 110, '生成时手动填写额度'],
  ];
  const insType = db.prepare(`INSERT OR IGNORE INTO card_types
    (app_id,code,name,unit,value,enabled,sort,remark,created_at) VALUES('default',?,?,?,?,1,?,?,?)`);
  for (const [code, name, unit, value, sort, remark] of defTypes) {
    try { insType.run(code, name, unit, value, sort, remark, t); } catch (e) {}
  }

  // 管理员：优先读环境变量，否则默认 admin/admin888
  if (!db.prepare('SELECT COUNT(*) c FROM admins').get().c) {
    const user = process.env.ADMIN_USER || 'admin';
    const pwd = process.env.ADMIN_PWD || 'admin888';
    const salt = crypto.randomBytes(8).toString('hex');
    db.prepare('INSERT INTO admins(username,password_hash,salt,created_at) VALUES(?,?,?,?)')
      .run(user, hashPassword(pwd, salt), salt, t);
    console.log(`[init] 管理员已创建: ${user} / ${pwd}`);
  }

  // 密钥：云端必须固定，否则重启后客户端签名失效
  const envSecret = process.env.API_SECRET;
  if (envSecret) setSetting('api_secret', envSecret);
  else if (!getSetting('api_secret')) {
    setSetting('api_secret', crypto.randomBytes(24).toString('hex'));
    console.log('[init] 已生成 API 通信密钥');
  }

  if (process.env.JWT_SECRET) setSetting('jwt_secret', process.env.JWT_SECRET);
  else if (!getSetting('jwt_secret')) setSetting('jwt_secret', crypto.randomBytes(32).toString('hex'));

  const defaults = {
    site_name: process.env.SITE_NAME || '释然团队',
    card_prefix: '',
    bind_device: '1',
    allow_rebind: '1',
    self_unbind: '1',
    recharge_rate: '1',
    sign_required: '1',
    agent_register_open: '1',
    client_ver: '1.0.0',
    download_url: '',
    heart_interval: '300',
  };
  for (const [k, v] of Object.entries(defaults)) {
    if (getSetting(k) === null) setSetting(k, v);
  }
}
init();

module.exports = { db, now, hashPassword, getSetting, setSetting, DATA_DIR, DB_PATH };
