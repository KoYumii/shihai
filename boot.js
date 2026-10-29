/* 静态版的「后端」：没有服务器，全靠这几包加密文件。
 * 页面上先要求口令 → WebCrypto 解出 core（图/尘埃/向量/事件索引），
 * 再把 window.fetch 里所有 /api/* 的请求就地答掉 —— 星图代码一行都不用改。
 */
(function () {
  const PASS_KEY = 'shihai.pass';
  const qs = new URLSearchParams(location.search);

  const state = {
    pass: qs.get('p') || localStorage.getItem(PASS_KEY) || '',
    core: null,
    loading: null,
    nodeById: new Map(),
    nodeByUid: new Map(),
    shards: new Map(),
    vecs: null,
  };

  /* ---------- 解密 ---------- */
  const te = new TextEncoder();
  const td = new TextDecoder();

  async function decrypt(buf, pass) {
    const bytes = new Uint8Array(buf);
    if (td.decode(bytes.subarray(0, 5)) !== 'SHIH1') throw new Error('文件格式不对');
    const salt = bytes.subarray(5, 21);
    const iv = bytes.subarray(21, 33);
    const tag = bytes.subarray(33, 49);
    const body = bytes.subarray(49);
    const base = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, concat(body, tag));
    return td.decode(plain);
  }
  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }
  async function grab(path) {
    const r = await fetch(path, { cache: 'force-cache' });
    if (!r.ok) throw new Error(path + ' → HTTP ' + r.status);
    return r.arrayBuffer();
  }

  /* ---------- 口令界面 ---------- */
  function askPass() {
    return new Promise((res) => {
      const box = document.createElement('div');
      box.style.cssText = 'position:fixed;inset:0;z-index:99;display:flex;align-items:center;justify-content:center;background:#04060a';
      box.innerHTML =
        '<div style="width:min(320px,80vw);text-align:center">' +
        '<div style="font-size:13px;letter-spacing:.22em;color:#93a4bb;margin-bottom:18px">识 海</div>' +
        '<input id="pw" type="password" autocomplete="current-password" placeholder="口令" ' +
        'style="width:100%;padding:11px 13px;background:rgba(120,150,190,.08);border:1px solid rgba(120,150,190,.22);' +
        'border-radius:8px;color:#dbe5f2;font-size:14px;letter-spacing:.18em;outline:none">' +
        '<button id="go" style="margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;' +
        'background:rgba(150,180,220,.16);color:#c8d6e8;font-size:13px;letter-spacing:.2em;cursor:pointer">进 入</button>' +
        '<div id="err" style="margin-top:12px;font-size:11px;color:#8a6a6a;min-height:14px"></div></div>';
      document.body.appendChild(box);
      const input = box.querySelector('#pw');
      const err = box.querySelector('#err');
      const submit = async () => {
        const p = input.value.trim();
        if (!p) return;
        err.textContent = '解密中…'; err.style.color = '#7e8ea3';
        localStorage.setItem(PASS_KEY, p);
        state.pass = p;
        try {
          await loadCore();
          box.remove();
          res();
        } catch (e) {
          localStorage.removeItem(PASS_KEY);
          state.pass = '';
          err.textContent = '口令不对'; err.style.color = '#8a6a6a';
        }
      };
      box.querySelector('#go').onclick = submit;
      input.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
      setTimeout(() => input.focus(), 60);
    });
  }

  /* ---------- 载入 core ---------- */
  async function loadCore() {
    if (state.core) return state.core;
    if (state.loading) return state.loading;
    state.loading = (async () => {
      if (!state.pass) { await askPass(); if (!state.core) return state.core; }
      const buf = await grab('data/core.enc');
      let json;
      try { json = JSON.parse(await decrypt(buf, state.pass)); }
      catch (e) { state.loading = null; throw e; }
      const core = json;
      for (const n of core.graphs.real.nodes) { state.nodeById.set(n.id, n); state.nodeByUid.set(n.uid, n); }
      const v = core.vectors;
      const raw = Uint8Array.from(atob(v.data), (c) => c.charCodeAt(0));
      const flat = new Float32Array(raw.buffer);
      const map = new Map();
      v.ids.forEach((id, i) => map.set(id, flat.subarray(i * v.dim, (i + 1) * v.dim)));
      state.vecs = map;
      state.core = core;
      return core;
    })();
    return state.loading;
  }

  async function ensureShard(i) {
    if (state.shards.has(i)) return state.shards.get(i);
    const json = JSON.parse(await decrypt(await grab('data/ev-' + i + '.enc'), state.pass));
    state.shards.set(i, json);
    return json;
  }

  /* ---------- 和 serve.mjs 同口径的相似度 ---------- */
  function similar(uid, k, min) {
    const p = state.nodeByUid.get(uid);
    if (!p || !state.vecs) return { items: [] };
    const base = state.vecs.get(p.id);
    if (!base) return { items: [] };
    const out = [];
    for (const [id, v] of state.vecs) {
      if (id === p.id) continue;
      let dot = 0;
      const n = Math.min(base.length, v.length);
      for (let i = 0; i < n; i++) dot += base[i] * v[i];
      if (dot >= min) out.push({ id, cos: dot });
    }
    out.sort((x, y) => y.cos - x.cos);
    return {
      uid: p.uid, title: p.title,
      items: out.slice(0, k).map((x) => {
        const q = state.nodeById.get(x.id);
        return { id: x.id, uid: q && q.uid, title: q && q.title, cos: Math.round(x.cos * 1e3) / 1e3 };
      }),
    };
  }

  /* ---------- 把 /api/* 接住 ---------- */
  const json = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } });

  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (!url.startsWith('/api/') && !url.includes('/api/')) return realFetch(input, init);
    const u = new URL(url, location.href);
    await loadCore();
    if (u.pathname === '/api/graph') return json(state.core.graphs[u.searchParams.get('mode') || 'real']);
    if (u.pathname === '/api/dust') return json(state.core.dust);
    if (u.pathname === '/api/glow') return json(state.core.glow);
    if (u.pathname === '/api/similar') {
      return json(similar(u.searchParams.get('uid'), Number(u.searchParams.get('k') || 8), Number(u.searchParams.get('min') || 0.45)));
    }
    if (u.pathname === '/api/event') {
      const uid = u.searchParams.get('uid');
      const i = state.core.index[uid];
      if (i === undefined) return new Response(JSON.stringify({ error: '没有这个点' }), { status: 404 });
      const shard = await ensureShard(i);
      return json(shard[uid]);
    }
    return new Response(JSON.stringify({ error: 'not found' }), { status: 404 });
  };

  // 先踢一脚：让口令框在画布空转之前就出来
  loadCore().catch(() => {});
})();
