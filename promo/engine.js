// Film engine. The whole film is a pure function of time: P.seek(T) puts every scene, the background and the
// transitions in the exact state for master time T (seconds). No CSS animations, timers or Math.random anywhere,
// so the preview, a scrub and the frame-by-frame render all show the same picture.
(function () {
  'use strict';
  const P = window.P = { W: 1920, H: 1080, scenes: [], cues: [], wipes: [], k: 1, T: 0 };

  // ---------- math ----------
  const clamp = P.clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const lerp = P.lerp = (a, b, p) => a + (b - a) * p;
  const spring = (z, w) => (p) => (p >= 1 ? 1 : 1 - Math.exp(-z * p) * Math.cos(w * p));
  const E = P.ease = {
    linear: (p) => p,
    inOutSine: (p) => -(Math.cos(Math.PI * p) - 1) / 2,
    inCubic: (p) => p * p * p,
    outCubic: (p) => 1 - (1 - p) ** 3,
    inOutCubic: (p) => (p < 0.5 ? 4 * p * p * p : 1 - (-2 * p + 2) ** 3 / 2),
    outExpo: (p) => (p >= 1 ? 1 : 1 - 2 ** (-10 * p)),
    glide: (p) => (p < 0.5 ? 16 * p ** 5 : 1 - (-2 * p + 2) ** 5 / 2),
    settle: spring(9, 10), // big objects, ~6 % overshoot
    pop: spring(7, 14),    // small things, ~20 % overshoot
  };
  const ez = (e) => (typeof e === 'function' ? e : E[e] || E.outCubic);
  // eased progress of an event that starts at t0 and lasts dur
  P.tw = (t, t0, dur, e) => ez(e)(clamp((t - t0) / dur));
  P.map = (t, t0, t1, a, b, e) => lerp(a, b, ez(e)(clamp((t - t0) / (t1 - t0))));
  P.rng = (seed) => () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let x = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
  P.hash = (n) => P.rng(n * 9973 + 17)();
  // quadratic arc from a to b, lifted by `lift` px (negative = up)
  P.arc = (a, b, lift, p) => {
    const cx = (a.x + b.x) / 2, cy = (a.y + b.y) / 2 + lift, q = 1 - p;
    return { x: q * q * a.x + 2 * q * p * cx + p * p * b.x, y: q * q * a.y + 2 * q * p * cy + p * p * b.y };
  };

  // ---------- DOM ----------
  P.esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  P.el = (parent, tag, cls, html, css) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    if (css) e.style.cssText = css;
    if (parent) parent.appendChild(e);
    return e;
  };
  // transform + opacity + blur; nothing carries over between calls
  P.xf = (el, o = {}) => {
    const s = o.s == null ? 1 : o.s;
    el.style.transform = `translate(${o.x || 0}px,${o.y || 0}px) rotate(${o.r || 0}deg) scale(${o.sx == null ? s : o.sx},${o.sy == null ? s : o.sy})`;
    el.style.opacity = o.o == null ? 1 : clamp(o.o);
    el.style.filter = o.blur > 0.05 ? `blur(${o.blur.toFixed(2)}px)` : '';
  };
  // element rect in stage pixels (layout only: call in build, before any transform is set)
  P.rect = (el) => {
    const r = el.getBoundingClientRect(), s = P.stage.getBoundingClientRect();
    return { x: (r.left - s.left) / P.k, y: (r.top - s.top) / P.k, w: r.width / P.k, h: r.height / P.k,
      get cx() { return this.x + this.w / 2; }, get cy() { return this.y + this.h / 2; } };
  };
  // shrink font-size until the element fits maxW (and maxH when given); translations stay inside the frame
  P.fit = (el, maxW, maxPx, minPx, maxH) => {
    let px = maxPx;
    el.style.fontSize = px + 'px';
    while (px > minPx && (el.scrollWidth > maxW + 0.5 || (maxH && el.scrollHeight > maxH + 0.5))) {
      px -= 1;
      el.style.fontSize = px + 'px';
    }
    return px;
  };
  // text entrance: rise + unblur at t0, exit at t1 (optional)
  P.show = (el, t, t0, t1, o = {}) => {
    const dur = o.dur || 0.55, dy = o.dy == null ? 26 : o.dy;
    const a = P.tw(t, t0, dur, o.ease || 'outCubic');
    const b = t1 == null ? 0 : P.tw(t, t1, o.out || 0.35, 'inOutSine');
    P.xf(el, { x: o.dx ? o.dx * (1 - a) : 0, y: dy * (1 - a) - (o.up == null ? 18 : o.up) * b, o: a * (1 - b), blur: (o.blur == null ? 10 : o.blur) * (1 - a) + 6 * b, s: o.s ? lerp(o.s, 1, a) : 1 });
  };
  P.pop = (el, t, t0, t1, o = {}) => {
    const a = P.tw(t, t0, o.dur || 0.6, 'pop'), f = clamp((t - t0) / 0.12);
    const b = t1 == null ? 0 : P.tw(t, t1, 0.3, 'inOutSine');
    P.xf(el, { x: o.x || 0, y: (o.y || 0) - 10 * b, s: Math.max(0, (o.s || 1) * (0.4 + 0.6 * a) * (1 - 0.15 * b)), o: f * (1 - b) });
  };

  const ICON = {
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    devices: '<rect x="2.5" y="4" width="13" height="9" rx="1.5"/><path d="M1 16.5h12"/><rect x="16.5" y="8" width="6" height="12" rx="1.5"/>',
    database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/><path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3"/>',
    bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    server: '<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
    key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M16 7l3 3M19 4l2 2"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    flame: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.07-2.14-.22-4.05 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.15.43-2.29 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>',
    gone: '<circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    chat: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    mail: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-2.82 1.17V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 3.6 15H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 3.6V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 2.82 1.17l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    clip: '<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
    timer: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2M10 2h4"/>',
    up: '<path d="M12 19V5M5 12l7-7 7 7"/>',
    term: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 9 3 3-3 3M12 15h6"/>',
    chip: '<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9zM9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/>',
    sign: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9.5 12.5h5M12 10v5"/>',
    qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM18 18h3v3h-3zM14 20h2M20 14v2"/>',
    users: '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0"/><path d="M16 4a4 4 0 0 1 0 8M18 14a6 6 0 0 1 4 7"/>',
    code: '<path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/>',
    eyeoff: '<path d="M9.9 4.24A9 9 0 0 1 12 4c7 0 10 8 10 8a13 13 0 0 1-1.67 2.68M6.61 6.61A13.5 13.5 0 0 0 2 12s3 8 10 8a9.7 9.7 0 0 0 5.39-1.61M2 2l20 20"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/>',
    ticket: '<path d="M3 7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v3a2 2 0 0 0 0 4v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 0 0-4z"/><path d="M13 5v2M13 11v2M13 17v2"/>',
    back: '<path d="m15 18-6-6 6-6"/>',
    alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    phone: '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/>',
    apps: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    spark: '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z"/><path d="M19 16l.7 1.8 1.8.7-1.8.7L19 21l-.7-1.8-1.8-.7 1.8-.7z"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  };
  P.icon = (name, size = 24, color = 'currentColor', sw = 2) =>
    `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="${color}" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${ICON[name]}</svg>`;

  // mouse pointer with a press ring
  P.pointer = (parent) => {
    const el = P.el(parent, 'div', 'ptr', '<div class="ring"></div><svg viewBox="0 0 24 24" width="46" height="46"><path d="M4 2v18l5-4.5 3.5 7 3-1.5-3.5-7H19z" fill="#fff" stroke="#10131c" stroke-width="1.4" stroke-linejoin="round"/></svg>');
    const ring = el.firstChild, arrow = el.lastChild;
    return {
      el,
      // press: 0..1 (button down), click: seconds since the click (ring), o: opacity
      set(x, y, o, press = 0, since = -1) {
        P.xf(el, { x, y, o });
        P.xf(arrow, { s: 1 - 0.14 * press });
        const r = since >= 0 ? clamp(since / 0.45) : 1;
        P.xf(ring, { s: 0.3 + 1.2 * E.outCubic(r), o: since >= 0 ? (1 - r) * 0.9 : 0 });
      },
    };
  };

  // typing into a pre-wrap box. segs: [{text, cls, t0, cps}] (cps 0 = pasted at t0). Emits key/paste cues.
  P.typer = (box, segs, cue) => {
    const parts = segs.map((s) => {
      const on = P.el(box, 'span', s.cls || ''), off = P.el(box, 'span', (s.cls || '') + ' ghost', P.esc(s.text));
      return { s, on, off, n: -1 };
    });
    const caret = P.el(null, 'span', 'caret');
    for (const s of segs) {
      if (!s.cps) { cue(s.t0, 'paste'); continue; }
      [...s.text].forEach((ch, i) => { if (ch !== ' ' && ch !== '\n' && i % 2 === 0) cue(s.t0 + i / s.cps, ch === '\n' ? 'enter' : 'key', { i }); });
    }
    return {
      parts,
      set(t, showCaret = true) {
        let last = parts[0];
        for (const p of parts) {
          const len = p.s.text.length;
          const n = p.s.cps ? clamp(Math.floor((t - p.s.t0) * p.s.cps) + 1, 0, len) : t >= p.s.t0 ? len : 0;
          if (n !== p.n) { p.on.textContent = p.s.text.slice(0, n); p.off.textContent = p.s.text.slice(n); p.n = n; }
          if (n > 0) last = p;
        }
        if (showCaret && caret.previousSibling !== last.on) last.on.after(caret);
        caret.style.opacity = showCaret && Math.floor(t * 2.2) % 2 === 0 ? 1 : showCaret ? 0.25 : 0;
      },
      done: (t) => segs.every((s) => t >= s.t0 + (s.cps ? s.text.length / s.cps : 0)),
    };
  };

  // ---------- scenes ----------
  // def: {id, dur, build(root, S, cue), update(t), trans?: {type: 'ff'|'rw'|'fade', dur, label}} (trans = cut INTO this scene)
  P.scene = (def) => P.scenes.push(def);
  P.info = (id) => P.scenes.find((s) => s.id === id);
  // overlay that lives across scenes (timeline HUD): {build(el, S, cue), update(T)}
  P.overlay = null;
  P.trans = [];

  // accent colours for particles: SecNote slate blue → lavender
  const BRAND = [[110, 143, 192], [160, 170, 240], [221, 221, 240]];
  P.brand = (u, a = 1, lift = 0) => {
    u = clamp(u);
    const i = u < 0.5 ? 0 : 1, f = u < 0.5 ? u * 2 : u * 2 - 1, A = BRAND[i], B = BRAND[i + 1];
    const c = A.map((v, k) => Math.round(clamp(lerp(v, B[k], f) + lift, 0, 255)));
    return `rgba(${c[0]},${c[1]},${c[2]},${a})`;
  };

  // SecNote's dot grid (website/og.svg), drifting slowly, a few dots breathing
  function drawBackground(ctx, T) {
    ctx.clearRect(0, 0, P.W, P.H);
    const g = 40, ox = (T * 7) % g, oy = (T * 3.5) % g;
    for (let j = -1; j <= P.H / g + 1; j++) for (let i = -1; i <= P.W / g + 1; i++) {
      const n = P.hash(i * 977 + j * 131 + 5), a = 0.06 + (n > 0.9 ? 0.16 * (0.5 + 0.5 * Math.sin(T * 1.7 + n * 60)) : 0.03 * n);
      ctx.fillStyle = `rgba(221,221,240,${a.toFixed(3)})`;
      ctx.beginPath(); ctx.arc(i * g + ox, j * g + oy, n > 0.9 ? 1.8 : 1.3, 0, 6.2832); ctx.fill();
    }
  }

  const pmod = (a, m) => ((a % m) + m) % m;
  // cuts: fast-forward streaks, a tape rewind (streaks the other way, scanlines, colour split) or a dark dip
  function drawTrans(ctx, T) {
    ctx.clearRect(0, 0, P.W, P.H);
    for (const w of P.trans) {
      const d = w.dur || 1.2, u = (T - (w.at - d / 2)) / d;
      if (u <= 0 || u >= 1) continue;
      const peak = Math.sin(Math.PI * u) ** 0.7;
      ctx.fillStyle = `rgba(6,7,16,${(w.type === 'fade' ? 1 : 0.9) * peak})`;
      ctx.fillRect(0, 0, P.W, P.H);
      const dir = w.type === 'rw' ? -1 : 1;
      if (w.type !== 'fade') {
        for (let k = 0; k < 70; k++) {
          const r = P.rng(k * 17 + Math.round(w.at * 10)), y = r() * P.H, len = 150 + r() * 900, sp = 2600 + r() * 4200;
          const x = pmod(r() * 4000 + dir * (T - w.at) * sp, P.W + len);
          const a = peak * (0.12 + 0.45 * r());
          ctx.fillStyle = w.type === 'rw' ? (k % 2 ? `rgba(255,96,110,${a})` : `rgba(96,200,255,${a})`) : `rgba(180,195,255,${a})`;
          ctx.fillRect(dir > 0 ? x - len : x - len, y, len, 1 + r() * 3);
        }
        if (w.type === 'rw') for (let y = 0; y < P.H; y += 6) { ctx.fillStyle = `rgba(255,255,255,${0.035 * peak})`; ctx.fillRect(0, y, P.W, 2); }
      }
      if (w.label) {
        ctx.save();
        ctx.globalAlpha = clamp(peak * 1.4);
        ctx.font = '500 64px "Roboto Mono"'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        const tx = P.W / 2 + dir * 30 * (u - 0.5);
        if (w.type === 'rw') { ctx.fillStyle = 'rgba(255,96,110,.8)'; ctx.fillText(w.label, tx - 3, P.H / 2); ctx.fillStyle = 'rgba(96,200,255,.8)'; ctx.fillText(w.label, tx + 3, P.H / 2); }
        ctx.fillStyle = '#eef0ff'; ctx.fillText(w.label, tx, P.H / 2);
        if (w.type !== 'fade') {
          // ▶▶ / ◀◀ above the label
          ctx.beginPath();
          for (const off of [-22, 22]) { const cx = tx + off, cy = P.H / 2 - 80; ctx.moveTo(cx - 18 * dir, cy - 18); ctx.lineTo(cx + 18 * dir, cy); ctx.lineTo(cx - 18 * dir, cy + 18); ctx.closePath(); }
          ctx.fill();
        }
        ctx.restore();
      }
    }
    // fade in from black at the start, out to black at the end
    const fade = Math.max(1 - clamp(T / 0.4), clamp((T - (P.total - 0.9)) / 0.8));
    if (fade > 0) { ctx.fillStyle = `rgba(3,4,10,${fade})`; ctx.fillRect(0, 0, P.W, P.H); }
  }

  P.build = (stage, S) => {
    P.stage = stage;
    const bg = stage.querySelector('#bg'), fx = stage.querySelector('#fx'), holder = stage.querySelector('#scenes');
    P.bgCtx = bg.getContext('2d'); P.fxCtx = fx.getContext('2d');
    let start = 0;
    for (const sc of P.scenes) { sc.start = start; sc.end = start + sc.dur; start = sc.end; }
    P.total = start;
    for (const sc of P.scenes) {
      sc.root = P.el(holder, 'div', 'scene ' + sc.id);
      sc.build(sc.root, S, (t, n, o) => P.cues.push({ t: sc.start + t, n, ...(o || {}) }));
      if (sc.trans) P.trans.push({ at: sc.start, ...sc.trans });
    }
    if (P.overlay) {
      P.overlay.el = P.el(null, 'div', 'overlay');
      holder.after(P.overlay.el);
      P.overlay.build(P.overlay.el, S, (t, n, o) => P.cues.push({ t, n, ...(o || {}) }));
    }
    P.cues.sort((a, b) => a.t - b.t);
  };

  P.seek = (T) => {
    T = clamp(T, 0, P.total - 1e-6);
    P.T = T;
    drawBackground(P.bgCtx, T);
    for (const sc of P.scenes) {
      const on = T >= sc.start - (sc.pre || 0) && T < sc.end;
      sc.root.style.visibility = on ? 'visible' : 'hidden';
      if (on) sc.update(T - sc.start);
    }
    if (P.overlay) P.overlay.update(T);
    drawTrans(P.fxCtx, T);
  };
})();
