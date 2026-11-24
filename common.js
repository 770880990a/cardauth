/* 公共 JS —— 请求封装 / 提示 / 工具 / 手机菜单 */
const API = '';

function toast(msg, type = '') {
  let el = document.getElementById('toast');
  if (!el) { el = document.createElement('div'); el.id = 'toast'; document.body.appendChild(el); }
  el.className = 'on ' + type;
  el.textContent = msg;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = type; el.style.opacity = 0; }, 2800);
}

function tokenGet(k) { return localStorage.getItem(k); }
function tokenSet(k, v) { localStorage.setItem(k, v); }
function tokenDel(k) { localStorage.removeItem(k); }

async function req(url, opt = {}, tokenKey = 'adm_token') {
  const headers = { 'Content-Type': 'application/json', ...(opt.headers || {}) };
  const t = tokenGet(tokenKey);
  if (t) headers.Authorization = 'Bearer ' + t;
  let res;
  try {
    res = await fetch(API + url, {
      method: opt.method || (opt.body ? 'POST' : 'GET'),
      headers,
      body: opt.body ? JSON.stringify(opt.body) : undefined,
    });
  } catch (e) {
    toast('网络错误，请检查服务是否在运行', 'err');
    throw e;
  }
  if (res.status === 401) {
    tokenDel(tokenKey);
    toast('登录已失效，请重新登录', 'err');
    setTimeout(() => { location.href = tokenKey === 'adm_token' ? 'admin.html' : 'agent.html'; }, 900);
    throw new Error('未登录');
  }
  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('json')) return await res.text();
  const j = await res.json();
  if (opt.raw) return j;
  if (j.code !== 0) { toast(j.msg || '操作失败', 'err'); throw new Error(j.msg || 'failed'); }
  return j;
}

function $(s, r = document) { return r.querySelector(s); }
function $$(s, r = document) { return [...r.querySelectorAll(s)]; }

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTime(ms) {
  if (!ms) return '-';
  const d = new Date(ms);
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function statusTag(st) {
  const m = {
    unused: ['未使用', 'wait'], used: ['已使用', 'ok'],
    expired: ['已过期', 'off'], disabled: ['已封禁', 'err'],
    pending: ['待审核', 'warn'], paid: ['已打款', 'ok'], rejected: ['已驳回', 'err'],
  };
  const [t, c] = m[st] || [st, 'off'];
  return `<span class="tag ${c}">${t}</span>`;
}

function copy(text) {
  const done = () => toast('已复制到剪贴板', 'ok');
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallback());
  } else fallback();
  function fallback() {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); }
    catch (e) { toast('复制失败，请长按手动选择', 'err'); }
    document.body.removeChild(ta);
  }
}

function download(filename, content, type = 'text/plain;charset=utf-8') {
  const blob = new Blob(['\ufeff' + content], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 3000);
}

/* 手机侧边栏 */
function initMobileNav() {
  const side = $('.side'), mask = $('.side-mask'), bg = $('.burger');
  if (!side || !bg) return;
  const close = () => { side.classList.remove('open'); mask && mask.classList.remove('on'); };
  bg.onclick = () => { side.classList.toggle('open'); mask && mask.classList.toggle('on'); };
  mask && (mask.onclick = close);
  $$('.side nav a').forEach(a => a.addEventListener('click', close));
}

function sideNav(items, active) {
  return items.map(([id, icon, name]) => `
    <a href="#${id}" data-tab="${id}" class="${id === active ? 'on' : ''}">
      <span>${icon}</span><em style="font-style:normal">${name}</em>
    </a>`).join('');
}

function openModal(title, bodyHtml, footHtml) {
  let m = document.getElementById('__modal');
  if (!m) {
    m = document.createElement('div');
    m.id = '__modal';
    m.className = 'mask';
    m.innerHTML = `<div class="modal">
      <div class="mh"><h3></h3><button class="x">&times;</button></div>
      <div class="mb"></div><div class="mf"></div></div>`;
    document.body.appendChild(m);
    m.querySelector('.x').onclick = closeModal;
    m.onclick = e => { if (e.target === m) closeModal(); };
  }
  m.querySelector('.mh h3').textContent = title;
  m.querySelector('.mb').innerHTML = bodyHtml;
  m.querySelector('.mf').innerHTML = footHtml || '';
  m.classList.add('on');
  return m;
}
function closeModal() {
  const m = document.getElementById('__modal');
  if (m) m.classList.remove('on');
}

/* 记录当前页签，刷新后保持 */
function tabRemember(key, def) {
  const h = (location.hash || '').replace('#', '');
  return h || sessionStorage.getItem(key) || def;
}
function tabSet(key, id) { sessionStorage.setItem(key, id); }
