'use strict';
/**
 * 同步 Worker RPC（结果走共享内存，彻底避开端口竞态）
 *
 * 共享内存布局（一个足够大的 SharedArrayBuffer）：
 *   [0]       Int32 状态位：0等待 1成功 2失败 3就绪 4初始化失败
 *   [1]       Int32 结果长度（字节，JSON UTF-8）
 *   [8..]     Uint8 结果数据区
 *
 * 流程：
 *   主线程：写请求到端口（postMessage）→ Atomics.wait 阻塞 → 醒来读长度和字节 → JSON.parse
 *   worker ：处理请求 → 把 JSON 结果写进共享内存 → 写长度 → notify
 *   因为结果在共享内存里，不依赖端口消息到达时机，无竞态。
 */

const { Worker, MessageChannel } = require('worker_threads');

const RESULT_CAPACITY = 16 * 1024 * 1024; // 16MB 结果区，足够大

function createSyncWorker(workerFile, workerData) {
  const channel = new MessageChannel();
  const port = channel.port1;

  // 1 个 Int32 状态 + 1 个 Int32 长度 + 数据区
  const headerBytes = 8;
  const sab = new SharedArrayBuffer(headerBytes + RESULT_CAPACITY);
  const signal = new Int32Array(sab, 0, 2);

  const worker = new Worker(workerFile, {
    workerData: {
      ...workerData,
      port: channel.port2,
      sharedBuf: sab,
      resultCapacity: RESULT_CAPACITY,
    },
    transferList: [channel.port2],
  });

  let dead = false;
  let deadReason = '';
  let ready = false;

  worker.on('error', e => { dead = true; deadReason = e.message; Atomics.store(signal, 0, 2); Atomics.notify(signal, 0); });
  worker.on('exit', c => { if (!dead) { dead = true; deadReason = 'worker exited (code ' + c + ')'; Atomics.store(signal, 0, 2); Atomics.notify(signal, 0); } });

  function waitReady(timeoutMs = 30000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const st = Atomics.load(signal, 0);
      if (st === 3) { ready = true; return true; }
      if (st === 4) throw new Error('DB 初始化失败: ' + deadReason);
      if (dead) throw new Error('DB worker 启动失败: ' + deadReason);
      if (Date.now() > deadline) throw new Error('DB worker 启动超时（30s）');
      Atomics.wait(signal, 0, st, 50);
    }
  }

  let seq = 0;

  function call(msg, timeoutMs = 60000) {
    if (dead) return { ok: false, error: 'DB worker 已停止: ' + deadReason };
    const id = ++seq;
    Atomics.store(signal, 0, 0);
    Atomics.store(signal, 1, 0);

    port.postMessage({ ...msg, id });

    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const st = Atomics.load(signal, 0);
      if (st === 1 || st === 2) break;
      if (dead) return { ok: false, error: 'DB worker 已停止: ' + deadReason };
      if (Date.now() > deadline) return { ok: false, error: 'DB 操作超时（' + timeoutMs + 'ms）' };
      Atomics.wait(signal, 0, st, 50);
    }

    const len = Atomics.load(signal, 1);
    if (len <= 0 || len > RESULT_CAPACITY) return { ok: false, error: '无效的 DB 响应长度 ' + len };

    const bytes = new Uint8Array(sab, headerBytes, len);
    let text;
    try {
      text = Buffer.from(bytes).toString('utf8');
    } catch (e) {
      return { ok: false, error: '读取 DB 响应失败' };
    }
    let reply;
    try { reply = JSON.parse(text); } catch (e) { return { ok: false, error: 'DB 响应解析失败: ' + text.slice(0, 120) }; }
    return reply;
  }

  return {
    call,
    waitReady,
    port,
    worker,
    close() {
      try { call({ type: 'close' }, 8000); } catch (e) {}
      try { worker.terminate(); } catch (e) {}
    },
  };
}

module.exports = { createSyncWorker, RESULT_CAPACITY };
