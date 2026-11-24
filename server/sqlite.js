'use strict';
/**
 * SQLite 适配层（多引擎自动降级）
 *
 * 优先级：
 *   1) node:sqlite       —— Node >= 22.5 内置，源码运行最快
 *   2) better-sqlite3    —— 装了原生模块则用（最快）
 *   3) sql.js (WASM)     —— 纯 JS 无原生依赖，打包成 EXE 时用这个
 *
 * 对外统一 API（better-sqlite3 风格）：
 *   db.prepare(sql).get(...)  / .all(...) / .run(...)
 *   db.exec(sql)  / db.transaction(fn)  / db.pragma(str)  / db.close()
 *
 * sql.js 是纯内存库，需要手动落盘；本适配层在每次写事务提交后自动持久化，
 * 并做原子写（先写 .tmp 再 rename），避免断电损坏。
 */

const fs = require('fs');
const path = require('path');

/* =========================================================
 *  SQL.js 引擎适配（Worker + 同步 RPC）
 * ========================================================= */
function createSqlJs(file) {
  const { createSyncWorker } = require('./sync-worker');

  // 定位 wasm
  const cands = [];
  if (typeof process.pkg !== 'undefined') {
    const exeDir = path.dirname(process.execPath);
    cands.push(path.join(exeDir, 'sql-wasm.wasm'));
    cands.push(path.join(exeDir, 'runtime', 'sql-wasm.wasm'));
  }
  try {
    cands.push(require.resolve('sql.js').replace(/sql-wasm\.js$/, 'sql-wasm.wasm'));
  } catch (e) {}
  cands.push(path.join(__dirname, '..', 'node_modules', 'sql.js', 'dist', 'sql-wasm.wasm'));

  let wasmPath = null;
  for (const c of cands) {
    try { if (c && fs.existsSync(c)) { wasmPath = c; break; } } catch (e) {}
  }
  if (!wasmPath) throw new Error('找不到 sql-wasm.wasm');

  // worker 入口：打包后需要用 pkg 的路径解析
  const workerFile = path.join(__dirname, 'sqljs-worker.js');

  const sw = createSyncWorker(workerFile, { file, wasmPath });
  sw.waitReady(60000);

  function normArgs(args) {
    if (args.length === 0) return undefined;
    if (args.length === 1 && args[0] !== null && typeof args[0] === 'object' && !Array.isArray(args[0])) {
      const o = {};
      for (const k of Object.keys(args[0])) {
        let v = args[0][k];
        if (v === undefined) v = null;
        if (typeof v === 'boolean') v = v ? 1 : 0;
        o[k] = v;
      }
      return o;
    }
    return args.map(v => {
      if (v === undefined) return null;
      if (typeof v === 'boolean') return v ? 1 : 0;
      return v;
    });
  }

  function check(r, sql) {
    if (!r.ok) throw new Error('[sql.js] ' + (r.error || '未知错误') + ' | SQL: ' + String(sql).slice(0, 150));
    return r.data;
  }

  let txDepth = 0;

  return {
    engine: 'sql.js',
    prepare(sql) {
      const isSelect = /^\s*(SELECT|WITH|PRAGMA)/i.test(sql);
      return {
        sql,
        get(...args) {
          const p = normArgs(args);
          const d = check(sw.call({ type: 'get', sql, params: p }), sql);
          return d === null ? undefined : d;
        },
        all(...args) {
          const p = normArgs(args);
          const d = check(sw.call({ type: 'all', sql, params: p }), sql);
          return d || [];
        },
        run(...args) {
          const p = normArgs(args);
          const d = check(sw.call({ type: 'run', sql, params: p }), sql);
          return d || { changes: 0, lastInsertRowid: 0 };
        },
      };
    },
    exec(sql) {
      check(sw.call({ type: 'exec', sql }), sql);
      return undefined;
    },
    pragma(str) {
      try { return sw.call({ type: 'pragma', sql: str }).data; } catch (e) { return null; }
    },
    transaction(fn) {
      const txCmd = sql => {
        const r = sw.call({ type: 'tx', sql });
        // 事务控制指令失败不抛错（sql.js 可能已自动提交），只记录
        return r;
      };
      // 每次调用都重新计算深度，避免闭包复用导致嵌套层级错乱
      return (...args) => {
        const depth = txDepth + 1;
        txDepth = depth;
        const sp = 'sp_' + depth;
        if (depth === 1) txCmd('BEGIN IMMEDIATE');
        else txCmd('SAVEPOINT ' + sp);

        try {
          const r = fn(...args);
          if (depth === 1) txCmd('COMMIT');
          else txCmd('RELEASE ' + sp);
          txDepth = depth - 1;
          return r;
        } catch (e) {
          if (depth === 1) txCmd('ROLLBACK');
          else txCmd('ROLLBACK TO ' + sp);
          txDepth = depth - 1;
          throw e;
        }
      };
    },
    close() {
      try { sw.call({ type: 'flush' }, 5000); } catch (e) {}
      try { sw.close(); } catch (e) {}
    },
    _flush() { try { sw.call({ type: 'flush' }); } catch (e) {} },
  };
}

/* =========================================================
 *  node:sqlite（Node 内置）
 * ========================================================= */
function createBuiltin(file) {
  const dynamicRequire = typeof __non_webpack_require__ === 'function'
    ? __non_webpack_require__
    : require;
  let mod;
  try {
    mod = dynamicRequire('node:sqlite');
  } catch (e) {
    mod = eval('require')('node' + ':sqlite');
  }
  const DatabaseSync = mod && mod.DatabaseSync;
  if (!DatabaseSync) throw new Error('node:sqlite 不可用');
  const raw = new DatabaseSync(file);

  const norm = args => args.map(a => {
    if (a === undefined) return null;
    if (typeof a === 'boolean') return a ? 1 : 0;
    return a;
  });
  const plain = row => {
    if (row === null || typeof row !== 'object') return row;
    const o = {};
    for (const k of Object.keys(row)) o[k] = row[k];
    return o;
  };

  let txDepth = 0;
  return {
    _raw: raw,
    prepare(sql) {
      const stmt = raw.prepare(sql);
      return {
        sql,
        get(...a) { const r = stmt.get(...norm(a)); return r === undefined ? undefined : plain(r); },
        all(...a) { return stmt.all(...norm(a)).map(plain); },
        run(...a) {
          const r = stmt.run(...norm(a));
          return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
        },
      };
    },
    exec(sql) { return raw.exec(sql); },
    pragma(str) { try { return raw.exec('PRAGMA ' + str); } catch (e) { return null; } },
    transaction(fn) {
      return (...args) => {
        txDepth++;
        const sp = 'sp_' + txDepth;
        try {
          if (txDepth === 1) raw.exec('BEGIN IMMEDIATE');
          else raw.exec('SAVEPOINT ' + sp);
        } catch (e) { txDepth--; throw e; }
        try {
          const r = fn(...args);
          if (txDepth === 1) raw.exec('COMMIT');
          else raw.exec('RELEASE ' + sp);
          txDepth--;
          return r;
        } catch (e) {
          try {
            if (txDepth === 1) raw.exec('ROLLBACK');
            else raw.exec('ROLLBACK TO ' + sp);
          } catch (_) {}
          txDepth--;
          throw e;
        }
      };
    },
    close() { try { raw.close(); } catch (e) {} },
  };
}

/* =========================================================
 *  better-sqlite3
 * ========================================================= */
function createBetterSqlite(file) {
  const Database = require('better-sqlite3');
  return new Database(file);
}

/* =========================================================
 *  打开数据库
 * ========================================================= */
function open(file) {
  const dir = path.dirname(file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const PKG = typeof process.pkg !== 'undefined';
  const forceEngine = (process.env.DB_ENGINE || '').toLowerCase();

  const order = [];
  if (forceEngine) {
    order.push(forceEngine);
  } else if (PKG) {
    // 打包环境：优先纯 JS，避免原生模块 ABI 问题
    order.push('sqljs', 'builtin', 'native');
  } else {
    order.push('builtin', 'native', 'sqljs');
  }

  const errors = [];
  let db = null;
  let engine = '';

  for (const name of order) {
    try {
      if (name === 'builtin') { db = createBuiltin(file); engine = 'node:sqlite'; }
      else if (name === 'native') { db = createBetterSqlite(file); engine = 'better-sqlite3'; }
      else if (name === 'sqljs') { db = createSqlJs(file); engine = 'sql.js'; }
      if (db) break;
    } catch (e) {
      errors.push(`${name}: ${e.message}`);
    }
  }

  if (!db) throw new Error('无法初始化数据库：\n  ' + errors.join('\n  '));

  const pragma = s => {
    try {
      if (engine === 'sql.js') db.pragma(s);
      else if (engine === 'better-sqlite3') db.pragma(s);
      else db.pragma(s);
    } catch (e) {}
  };
  pragma('foreign_keys = ON');
  if (engine !== 'sql.js') {
    pragma('journal_mode = WAL');
    pragma('busy_timeout = 5000');
  }

  db.engine = engine;

  // 进程退出前确保落盘
  if (engine === 'sql.js') {
    const save = () => { try { db._flush(); } catch (e) {} };
    process.on('exit', save);
    process.on('SIGINT', () => { save(); process.exit(0); });
    process.on('SIGTERM', () => { save(); process.exit(0); });
  }

  return db;
}

module.exports = { open };
