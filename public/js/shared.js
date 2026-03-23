// shared.js — utilitários usados em todas as páginas

const API = window.location.origin + '/api';

// ─── CURSOR ──────────────────────────────────────────
let mx = window.innerWidth / 2, my = window.innerHeight / 2;
let rx = mx, ry = my;
const cur = document.getElementById('cur');
const curRing = document.getElementById('cur-ring');

document.addEventListener('mousemove', e => { mx = e.clientX; my = e.clientY; });

function cursorLoop() {
  if (cur) { cur.style.left = mx + 'px'; cur.style.top = my + 'px'; }
  rx += (mx - rx) * 0.13; ry += (my - ry) * 0.13;
  if (curRing) { curRing.style.left = rx + 'px'; curRing.style.top = ry + 'px'; }
  requestAnimationFrame(cursorLoop);
}
cursorLoop();

function hookHover(selectors = 'a,button,input,textarea,select,[data-hover]') {
  document.querySelectorAll(selectors).forEach(el => {
    el.addEventListener('mouseenter', () => document.body.classList.add('hov'));
    el.addEventListener('mouseleave', () => document.body.classList.remove('hov'));
  });
}

document.addEventListener('click', e => {
  const r = document.createElement('div');
  r.style.cssText = `position:fixed;left:${e.clientX}px;top:${e.clientY}px;width:4px;height:4px;border-radius:50%;background:rgba(168,240,176,0.6);pointer-events:none;z-index:9998;transform-origin:center;animation:ripple .6s ease forwards;`;
  document.body.appendChild(r);
  r.addEventListener('animationend', () => r.remove());
});

// ─── TOAST ───────────────────────────────────────────
function toast(msg, type = 'info') {
  const icons = { info: '💬', success: '✅', error: '❌', warn: '⚠️' };
  let wrap = document.querySelector('.toast-wrap');
  if (!wrap) { wrap = document.createElement('div'); wrap.className = 'toast-wrap'; document.body.appendChild(wrap); }

  const t = document.createElement('div');
  t.className = 'toast' + (type === 'error' ? ' error' : '');
  t.innerHTML = `<span>${icons[type]}</span><span>${msg}</span>`;
  wrap.appendChild(t);
  requestAnimationFrame(() => requestAnimationFrame(() => t.classList.add('show')));
  setTimeout(() => { t.classList.remove('show'); t.addEventListener('transitionend', () => t.remove()); }, 3500);
}

// ─── AUTH ─────────────────────────────────────────────
const Auth = {
  getToken: () => localStorage.getItem('mih_token'),
  getUser: () => { try { return JSON.parse(localStorage.getItem('mih_user')); } catch { return null; } },
  isLoggedIn: () => !!localStorage.getItem('mih_token'),
  isAdmin: () => { const u = Auth.getUser(); return u?.role === 'admin'; },
  logout: () => { localStorage.removeItem('mih_token'); localStorage.removeItem('mih_user'); window.location.href = '/login'; },
  headers: () => ({
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + Auth.getToken()
  }),

  async request(method, endpoint, body = null) {
    const opts = { method, headers: Auth.headers() };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(API + endpoint, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erro desconhecido');
    return data;
  },

  async get(endpoint) { return Auth.request('GET', endpoint); },
  async post(endpoint, body) { return Auth.request('POST', endpoint, body); },
  async patch(endpoint, body) { return Auth.request('PATCH', endpoint, body); },
  async delete(endpoint) { return Auth.request('DELETE', endpoint); },
};

// ─── NAME EFFECT ─────────────────────────────────────
function applyNameEffect(el, effect) {
  el.classList.remove('name-glow', 'name-rainbow', 'name-pulse');
  if (effect && effect !== 'none') el.classList.add('name-' + effect);
}

// ─── REVEAL ON SCROLL ────────────────────────────────
function initReveal() {
  const io = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('in'); });
  }, { threshold: 0.1 });
  document.querySelectorAll('.reveal').forEach(el => io.observe(el));
}

// ─── COUNTDOWN ───────────────────────────────────────
function countUp(el, target, duration = 1800) {
  const start = performance.now();
  const tick = now => {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(eased * target);
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

// ─── FORMAT DATE ─────────────────────────────────────
function fmtDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('pt-BR', { day:'2-digit', month:'short', year:'numeric' });
}

window.toast = toast;
window.Auth = Auth;
window.applyNameEffect = applyNameEffect;
window.initReveal = initReveal;
window.countUp = countUp;
window.fmtDate = fmtDate;
window.hookHover = hookHover;
