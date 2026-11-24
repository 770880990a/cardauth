'use strict';
/**
 * sql.js 数据库 Worker
 * 独立线程持有 sql.js 实例；结果写入共享内存，主线程同步读取。
 */
const { workerData } = require('worker_threads');
const fs = require('fs');

const port = workerData.port;
const sab = workerData.sharedBuf;
const CAP = workerData.resultCapacity;
const headerBytes = 8;
const signal = new Int32Array(sab, 0, 2);
const out = new Uint8Array(sab, headerBytes, CAP);

let SQL = null;
let db = null;
const file = workerData.file;
let dirty = false;
let flushTimer = null;

/* ---------- 落盘 ---------- */
function markDirty() {
  dirty = true;
  if (flushTimer) return;
  flushTimer = setTimeout(() => { flushTimer = null; flushSync(); }, 30);
  if (flushTimer.unref) flushTimer.unref();
}
function flushSync() {
  if (!dirty || !db) return;
  try {
    const data = db.export();
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, Buffer.from(data));
    fs.renameSync(tmp, file);
    dirty = false;
  } catch (e) {
    process.stderr.write('[sqljs] 落盘失败: ' + e.message + '\n');
  }
}

/* ---------- 写结果到共享内存 ---------- */
function writeResult(obj) {
  const buf = Buffer.from(JSON.stringify(obj), 'utf8');
  if (buf.length > CAP) {
    const small = Buffer.from(JSON.stringify({ ok: false, error: '结果过大（' + buf.length + ' 字节）' }), 'utf8');
    small.copy(out, 0);
    Atomics.store(signal, 1, Math.min(small.length, CAP));
  } else {
    buf.copy(out, 0);
    Atomics.store(signal, 1, buf.length);
  }
}

function respond(ok, data, error) {
  writeResult({ ok, data: data === undefined ? null : data, error: error || null });
  Atomics.store(signal, 0, ok ? 1 : 2);
  Atomics.notify(signal, 0);
}

/* ---------- 初始化 ---------- */
async function init() {
  const initSqlJs = require('sql.js');

  let wasmBinary = null;
  const cands = [];
  if (workerData.wasmPath) cands.push(workerData.wasmPath);
  try { cands.push(require.resolve('sql.js').replace(/sql-wasm\.js$/, 'sql-wasm.wasm')); } catch (e) {}
  for (const c of cands) {
    try { if (c && fs.existsSync(c)) { wasmBinary = fs.readFileSync(c); break; } } catch (e) {}
  }

  SQL = await initSqlJs(wasmBinary ? { wasmBinary } : {});

  if (fs.existsSync(file)) {
    const buf = fs.readFileSync(file);
    db = buf.length ? new SQL.Database(new Uint8Array(buf)) : new SQL.Database();
  } else {
    db = new SQL.Database();
  }
  try { db.run('PRAGMA foreign_keys = ON'); } catch (e) {}
}

/* ---------- 请求处理 ---------- */
port.on('message', (msg) => {
  const { type, sql, params } = msg;

  try {
    let data;
    switch (type) {
      case 'exec':
        db.run(sql);
        markDirty();
        data = null;
        break;

      case 'pragma':
        try { data = db.exec('PRAGMA ' + sql); } catch (e) { data = null; }
        break;

      case 'get': {
        const stmt = db.prepare(sql);
        try {
          if (params !== undefined && params !== null) stmt.bind(params);
          if (stmt.step()) {
            const cols = stmt.getColumnNames();
            const vals = stmt.get();
            const o = {};
            for (let i = 0; i < cols.length; i++) o[cols[i]] = vals[i];
            data = o;
          } else data = null;
        } finally { stmt.free(); }
        break;
      }

      case 'all': {
        const stmt = db.prepare(sql);
        const rows = [];
        try {
          if (params !== undefined && params !== null) stmt.bind(params);
          while (stmt.step()) {
            const cols = stmt.getColumnNames();
            const vals = stmt.get();
            const o = {};
            for (let i = 0; i < cols.length; i++) o[cols[i]] = vals[i];
            rows.push(o);
          }
        } finally { stmt.free(); }
        data = rows;
        break;
      }

      case 'run': {
        db.run(sql, params);
        const changes = db.getRowsModified();
        let lastId = 0;
        try {
          const r = db.exec('SELECT last_insert_rowid() AS id');
          if (r.length && r[0].values.length) lastId = r[0].values[0][0];
        } catch (e) {}
        markDirty();
        data = { changes: Number(changes) || 0, lastInsertRowid: Number(lastId) || 0 };
        break;
      }

      case 'tx': {
        try {
          db.run(sql);
        } catch (e) {
          if (/no transaction is active|no such savepoint|cannot (commit|rollback)/i.test(e.message)) {
            // 无害的事务控制错误，忽略
          } else {
            throw e;
          }
        }
        if (/^\s*COMMIT/i.test(sql)) { markDirty(); flushSync(); }
        data = null;
        break;
      }

      case 'flush':
        flushSync();
        data = true;
        break;

      case 'close':
        flushSync();
        try { db.close(); } catch (e) {}
        respond(true, true);
        setTimeout(() => process.exit(0), 80);
        return;

      case 'ping':
        data = 'pong';
        break;

      default:
        throw new Error('未知操作: ' + type);
    }
    respond(true, data);
  } catch (e) {
    respond(false, null, e.message + ' | SQL: ' + String(sql || '').slice(0, 180));
  }
});

init()
  .then(() => {
    port.postMessage({ type: 'ready' });
    Atomics.store(signal, 0, 3);
    Atomics.notify(signal, 0);
  })
  .catch(e => {
    process.stderr.write('[sqljs] 初始化失败: ' + e.message + '\n');
    Atomics.store(signal, 0, 4);
    Atomics.notify(signal, 0);
  });
