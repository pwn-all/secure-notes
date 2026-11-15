// Story: the question and a comparison with typical one-time secret apps → the app is not tied to a server → a case: four employees share passwords in four kinds of apps → months later the history leaks and every password is
// exposed → rewind: the same day with SecNote, the chats get one-time links that burn on reading → the same leak finds
// nothing → more everyday uses → AI agents → one admin installs SecNote for everyone → outro. Times inside a scene are local seconds; cue() schedules a sound.
// Words come from i18n/<lang>.js (S); nothing user-visible is written here.
(function () {
  'use strict';
  const P = window.P, E = P.ease, el = P.el, esc = P.esc, tw = P.tw, clamp = P.clamp, lerp = P.lerp;
  const ACC = '#5b4be0';
  const W = 760, H = 340;
  const GRID = [[160, 235], [1000, 235], [160, 605], [1000, 605]];
  const SMALL = [[220, 250], [220, 432], [220, 614], [220, 796]];
  const APPI = ['chat', 'phone', 'mail', 'ticket'];
  const HOWI = ['key', 'phone', 'mail', 'database'];

  // ---------- shared pieces ----------
  function caption(root, title, sub) {
    const box = el(root, 'div', 'cap');
    const t = el(box, 'div', 't', esc(title)), s = sub ? el(box, 'div', 's', esc(sub)) : null;
    P.fit(t, 1600, 54, 30);
    if (s) P.fit(s, 1600, 30, 21, 30 * 1.35 * 2 + 4);
    return (t_, t0, t1) => { P.show(t, t_, t0, t1, { blur: 8 }); if (s) P.show(s, t_, t0 + 0.4, t1); };
  }
  const ini = (n) => n.replace(/[^A-Za-z ]/g, '').trim().slice(0, 2).toUpperCase();
  const hl = (text, q) => esc(text).split(esc(q)).join(`<mark>${esc(q)}</mark>`);
  const scramble = (s, seed) => { const r = P.rng(seed), A = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789'; return [...s].map((c) => (c === ' ' ? c : A[Math.floor(r() * A.length)])).join(''); };
  const canvas = (root) => { const cv = el(root, 'canvas', 'abs'); cv.width = 1920; cv.height = 1080; cv.style.cssText = 'left:0;top:0'; return cv.getContext('2d'); };
  const set = (e, k, v) => { if (e[k] !== v) e[k] = v; };
  const link = (S, i, short) => `https://${S.org_host}/?p=${short ? S.ids[i].slice(0, 8) + '…' : S.ids[i]}`;
  // a note burning away: embers rising out of a box
  function embers(ctx, box, bt, seed, n = 60) {
    if (bt <= 0 || bt >= 1) return;
    for (let j = 0; j < n; j++) {
      const r = P.rng(seed + j), x0 = box.x + r() * box.w, y0 = box.y + r() * box.h, d = r() * 0.35;
      const p = clamp((bt - d) / (1 - d));
      if (p <= 0 || p >= 1) continue;
      const sz = (4 + r() * 9) * (1 - p);
      ctx.fillStyle = p < 0.35 ? `rgba(255,${Math.round(150 + 80 * r())},70,${1 - p})` : `rgba(170,170,190,${(1 - p) * 0.8})`;
      ctx.beginPath(); ctx.roundRect(x0 + Math.sin(p * 6 + j) * 12 * p, y0 - 90 * E.outCubic(p), sz, sz, sz * 0.25); ctx.fill();
    }
  }

  // ---------- the four apps (generic looks, no brands) ----------
  // mode 'plain': the password itself; 'link': a SecNote link instead
  function appWin(root, S, i, x, y, mode) {
    const A = S.apps[i];
    const val = mode === 'link' ? `<span class="lnk">${esc(link(S, i, true))}</span>` : `<span class="sec">${esc(S.secrets[i])}</span>`;
    const kind = `<span class="kind">${P.icon(APPI[i], 16, '#5d6377', 2.4)}${esc(A.kind)}</span>`;
    let html;
    if (i === 0) {
      html = `<div class="mside">${A.side.map((c, k) => `<div class="${k === 2 ? 'on' : ''}">${esc(c)}</div>`).join('')}</div><div class="mmain"><div class="mhd"><b>${esc(A.head)}</b></div>` +
        `<div class="mbody"><div class="mm"><div class="av" style="background:#3d8be0">${esc(ini(A.ask_who))}</div><div><div class="who">${esc(A.ask_who)}<i>10:40</i></div><div>${esc(A.ask)}</div></div></div>` +
        `<div class="mm snd"><div class="av" style="background:#6d4fd8">${esc(ini(A.who))}</div><div style="min-width:0"><div class="who">${esc(A.who)}<i>${A.time}</i></div><div>${esc(A.label)} ${val}</div></div></div></div></div>${kind}`;
    } else if (i === 1) {
      html = `<div class="mhd">${P.icon('back', 24, '#6b7387', 2.4)}<div class="av round" style="background:#e07a3f">${esc(ini(A.head))}</div><div><b>${esc(A.head)}</b><small>${esc(A.status)}</small></div></div>${kind}` +
        `<div class="mbody"><div class="b in">${esc(A.ask)}<i>10:42</i></div><div class="b out snd">${esc(A.label)} ${val}<i>${A.time}</i></div></div>`;
    } else if (i === 2) {
      html = `<div class="mhd">${P.icon('mail', 24, '#6b7387', 2.2)}<b>${esc(A.head)}</b></div>${kind}` +
        `<div class="mbody"><div class="mfrom"><div class="av round" style="background:#18a566">IT</div><div><b>${esc(A.from)}</b> &lt;${esc(A.addr)}&gt;<br><small>${esc(A.to)} · ${A.time}</small></div></div>` +
        `<div class="snd">${esc(A.hi)}<br>${esc(A.label)} ${val}</div></div>`;
    } else {
      html = `<div class="mhd">${P.icon('ticket', 24, '#6b7387', 2.2)}<b>${esc(A.head)}</b><span class="state">${esc(A.state)}</span></div>${kind}` +
        `<div class="mbody"><div class="mm snd"><div class="av" style="background:#c2410c">${esc(ini(A.who))}</div><div style="min-width:0"><div class="who">${esc(A.who)}<i>${A.time}</i></div><div>${esc(A.label)} ${val}</div></div></div></div>`;
    }
    const w = el(root, 'div', 'mw ' + ['team', 'msgr', 'mail', 'desk'][i], html, `left:${x}px;top:${y}px;height:${H}px`);
    return { w, x, y, snd: w.querySelector('.snd'), val: w.querySelector('.sec, .lnk'), red: el(w, 'div', 'red') };
  }
  // small windows on the left, attacker search on the right
  function shrinkTo(w, i, p, jitter = 0) {
    const [sx, sy] = SMALL[i];
    P.xf(w.w, { x: lerp(0, sx - w.x, p) + jitter, y: lerp(0, sy - w.y, p), s: lerp(1, 0.5, p) });
  }
  function attacker(root, S, mode) {
    const a = el(root, 'div', 'atk', `<div class="ah"><i></i>${esc(S.search_head)}<span>${esc(S.search_src)}</span></div>` +
      `<div class="as">${P.icon('search', 26, '#8b8fa6', 2.4)}<span class="q"></span></div><div class="rows"></div>` +
      `<div class="foot"><span>${esc(S.exposed)}</span><b>0 / 4</b></div>`);
    const rows = S.apps.map((A, i) => el(a.querySelector('.rows'), 'div', 'row',
      `<div class="src">${P.icon(APPI[i], 16, '#8b8fa6', 2.4)}${esc(A.kind)} · ${esc(A.head)} · ${esc(S.months[2])} 3</div>` +
      `<div class="hit">${hl(A.label, S.search_q)} ${mode === 'link' ? `<span class="dead">${esc(link(S, i, true))}</span>` : `<span class="bad">${esc(S.secrets[i])}</span>`}</div>`));
    const svg = el(null, 'div', 'links', `<svg width="1920" height="1080">${rows.map(() => `<path fill="none" stroke="${mode === 'link' ? 'rgba(122,162,255,.55)' : 'rgba(255,90,98,.7)'}" stroke-width="2.5" stroke-dasharray="7 8"/>`).join('')}</svg>`);
    root.appendChild(svg);
    const paths = [...svg.querySelectorAll('path')];
    const ends = rows.map((r) => P.rect(r));
    return {
      a, rows, foot: a.querySelector('.foot'), cnt: a.querySelector('.foot b'), q: a.querySelector('.q'),
      // a dashed line from each small window to its search hit
      lines(t, rowAt) {
        paths.forEach((p, i) => {
          const s = { x: SMALL[i][0] + W * 0.5, y: SMALL[i][1] + H * 0.25 }, e = { x: ends[i].x, y: ends[i].cy };
          const k = tw(t, rowAt(i) - 0.15, 0.4, 'outCubic'), m = { x: lerp(s.x, e.x, k), y: lerp(s.y, e.y, k) };
          p.setAttribute('d', `M${s.x} ${s.y} C${s.x + 160} ${s.y} ${m.x - 160} ${m.y} ${m.x} ${m.y}`);
          p.style.opacity = k > 0 ? 1 : 0;
          p.style.strokeDashoffset = -t * 40;
        });
      },
    };
  }

  // ---------- SecNote pieces (light theme of the real page) ----------
  function app(parent, x, y, w, h, U) {
    const a = el(parent, 'div', 'app', '', `left:${x}px;top:${y}px;width:${w}px;height:${h}px`);
    el(a, 'div', 'ahd', `<span class="brand">${P.icon('lock', 28, ACC, 2.4)}SecNote</span><span class="health"><i></i><span class="hs">${esc(U.online)}</span><span class="sep"></span>${P.icon('gear', 24, '#4d4d58', 2)}</span>`);
    return a;
  }
  function composer(parent, x, y, w, U) {
    const c = el(parent, 'div', 'composer', '', `left:${x}px;top:${y}px;width:${w}px`);
    const ct = el(c, 'div', 'ctext');
    const ph = el(ct, 'span', 'phd', esc(U.composer_ph));
    el(c, 'div', 'crow', `${P.icon('clip', 26, '#4d4d58', 2)}<span class="ttlc">${P.icon('timer', 20, '#4d4d58', 2.2)}12h</span><span class="sp"></span><span class="sendc">${P.icon('up', 26, '#868692', 2.4)}</span>`);
    return { c, ct, ph, send: c.querySelector('.sendc') };
  }
  const ava = () => `<div class="ava">${P.icon('lock', 24, ACC, 2.4)}</div>`;
  const dotsAt = (dots, t) => dots.forEach((d, i) => { const k = Math.max(0, Math.sin(t * 7 - i * 0.9)); P.xf(d, { y: -5 * k, o: 0.45 + 0.55 * k }); });
  const LOCK = (size, color) => `<svg viewBox="15 12 50 59" width="${(size * 50 / 59).toFixed(1)}" height="${size}" style="display:block;overflow:visible"><g class="shk"><path d="M27 38V29A13 13 0 0 1 53 29V38" fill="none" stroke="${color}" stroke-width="4.5" stroke-linecap="round"/></g>` +
    `<rect x="17" y="38" width="46" height="31" rx="7" fill="${color}"/><circle cx="40" cy="51" r="5" fill="#101020"/><rect x="37.5" y="51" width="5" height="10" rx="2" fill="#101020"/></svg>`;

  // ---------- timeline HUD: without / with, the date, fast-forward and rewind ----------
  {
    let hud, mode, modeT, fill, head, date, S_;
    const D0 = Date.UTC(2026, 2, 3), D1 = Date.UTC(2026, 8, 14), SPAN = (D1 - D0) / 864e5;
    P.overlay = {
      build(root, S, cue) {
        S_ = S;
        hud = el(root, 'div', 'hud');
        mode = el(hud, 'div', 'mode bad', '<i></i><span></span>'); modeT = mode.lastChild;
        const track = el(hud, 'div', 'track');
        for (let m = 3; m <= 8; m++) el(track, 'div', 'tk', esc(S.months[m]), `left:${((Date.UTC(2026, m, 1) - D0) / (D1 - D0) * 100).toFixed(2)}%`);
        fill = el(track, 'div', 'fill'); head = el(track, 'div', 'head'); date = el(head, 'div', 'date');
        // the date rolls with a ratchet sound
        const L = P.info('leak').start, R = P.info('rewind').start, L2 = P.info('leak2').start;
        for (const [a, b] of [[L - 0.3, L + 1.2], [R - 0.5, R + 0.9], [L2 - 0.3, L2 + 1.2]]) for (let t = a; t < b; t += 0.07) cue(t, 'tick');
      },
      update(T) {
        const S0 = P.info('share').start, L = P.info('leak').start, R = P.info('rewind').start, L2 = P.info('leak2').start, U0 = P.info('uses').start;
        P.xf(hud, { o: clamp((T - S0 - 0.3) / 0.5) * (1 - tw(T, U0 - 0.7, 0.4)), y: 20 * (1 - tw(T, S0 + 0.3, 0.6, 'outCubic')) });
        const p = T < R - 0.5 ? tw(T, L - 0.3, 1.5, 'inOutCubic') : T < L2 - 0.3 ? 1 - tw(T, R - 0.5, 1.4, 'inOutCubic') : tw(T, L2 - 0.3, 1.5, 'inOutCubic');
        const good = T >= R;
        mode.className = 'mode ' + (good ? 'good' : 'bad');
        set(modeT, 'textContent', good ? S_.mode_with : S_.mode_without);
        fill.style.width = head.style.left = (p * 100).toFixed(2) + '%';
        const d = new Date(D0 + Math.round(p * SPAN) * 864e5);
        // minutes run while the four messages go out (10:41 … 10:44)
        const min = 40 + clamp(Math.floor(T - (good ? R + 5.6 : S0 + 0.3)), 0, 4);
        const time = p >= 1 ? '03:12' : p <= 0 ? `10:${min}` : '';
        set(date, 'textContent', `${S_.months[d.getUTCMonth()]} ${d.getUTCDate()}${time ? ' · ' + time : ''}`);
      },
    };
  }

  // =====================================================================================
  // 0. COMPARE — the question, then SecNote next to typical one-time secret apps, row by row
  // =====================================================================================
  {
    let q, qs, qty, cap, col, hd, rows, expls, summary, src;
    const C0 = 4.0, R = (i) => 5.6 + i * 2.6, N = 7, SUM = R(N) + 0.3;
    const X = 220, LW = 600, CW = 440, Y = 236, HH = 100, RH = 66;
    P.scene({
      id: 'compare', dur: 28,
      build(root, S, cue) {
        const C = S.cmp;
        q = el(root, 'div', 'bigq', '', 'top:400px');
        qty = P.typer(q, [{ text: C.intro, t0: 0.4, cps: 24 }], cue);
        qs = el(root, 'div', 'lead', esc(C.intro_sub), 'top:520px');
        P.fit(qs, 1600, 34, 22, 100);
        cap = caption(root, C.title, C.sub);
        const tbl = el(root, 'div', 'tbl', '', `left:${X}px;top:${Y}px;width:${LW + 2 * CW}px;height:${HH + N * RH}px`);
        col = el(tbl, 'div', 'tcol', '', `left:${LW + CW}px;top:-8px;width:${CW}px;height:${HH + N * RH + 16}px;transform-origin:50% 0`);
        hd = el(tbl, 'div', 'thd', `<div style="width:${LW}px"></div><div class="h" style="width:${CW}px">${esc(C.others)}<small>${esc(C.others_sub)}</small></div>` +
          `<div class="h s" style="width:${CW}px">${LOCK(40, '#ddddf0')}SecNote</div>`, `top:0;height:${HH}px`);
        const IC = { yes: P.icon('check', 20, '#3ecf8e', 3), part: P.icon('alert', 20, '#f5b544', 2.4), no: P.icon('x', 20, '#ff5a62', 3) };
        rows = C.rows.map((r, i) => {
          const e = el(tbl, 'div', 'trow', `<div class="tl" style="width:${LW}px">${esc(r.label)}${r.key ? `<span class="key">${P.icon('spark', 15, '#1b1b2e', 2.4)}${esc(r.key)}</span>` : ''}</div>` +
            `<div class="tv ${r.o[0]}" style="width:${CW}px"><span class="ic">${IC[r.o[0]]}</span><span>${esc(r.o[1])}</span></div>` +
            `<div class="tv yes" style="width:${CW}px"><span class="ic">${IC.yes}</span><span>${esc(r.s)}</span></div>`, `top:${HH + i * RH}px;height:${RH}px;width:${LW + 2 * CW}px`);
          const [l, o, sv] = e.children;
          [o, sv].forEach((c) => { c.lastChild.style.display = 'inline-block'; P.fit(c.lastChild, CW - 100, 21, 14); });
          return { e, l, o, s: sv, kind: r.o[0] };
        });
        expls = C.rows.map((r) => { const x = el(root, 'div', 'expl', esc(r.e), 'top:878px'); P.fit(x, 1600, 31, 22, 84); return x; });
        summary = el(root, 'div', 'expl', esc(C.summary), 'top:878px;color:#fff;font-weight:800');
        P.fit(summary, 1600, 34, 22, 90);
        src = el(root, 'div', 'srcnote', esc(C.source), `top:${Y + HH + N * RH + 16}px`);
        cue(3.3, 'whoosh', { dur: 0.7 }); cue(C0, 'pop', { note: 'C5', gain: 0.5 });
        rows.forEach((r, i) => {
          cue(R(i), 'tick');
          cue(R(i) + 0.45, r.kind === 'yes' ? 'chip' : 'pop', { note: r.kind === 'yes' ? 'G5' : r.kind === 'part' ? 'E4' : 'C4', gain: 0.45 });
          cue(R(i) + 0.9, 'chip', { note: ['C5', 'D5', 'E5', 'G5', 'A5', 'C6', 'E6'][i] });
        });
        cue(SUM, 'chime', { notes: ['C6', 'E6', 'G6', 'C7'] });
      },
      update(t) {
        // the question
        qty.set(t, t > 0.3 && t < 3.2);
        P.show(q, t, 0.2, 3.2, { dy: 0, blur: 0 });
        P.show(qs, t, 1.8, 3.2);
        // the table
        cap(t, 3.5);
        P.show(hd, t, C0, null, { dy: 20, blur: 4 });
        const c = tw(t, C0, 0.8, 'outCubic');
        P.xf(col, { o: c, sy: lerp(0.15, 1, c) });
        const g = tw(t, SUM, 0.6);
        col.style.boxShadow = g > 0 ? `0 0 ${(60 * g).toFixed(1)}px rgba(110,143,192,${(0.6 * g).toFixed(3)})` : '';
        rows.forEach((r, i) => {
          P.show(r.l, t, R(i), null, { dx: -30, dy: 0, blur: 4 });
          P.pop(r.o, t, R(i) + 0.45);
          P.pop(r.s, t, R(i) + 0.9);
          r.o.style.filter = g > 0 ? `saturate(${(1 - 0.6 * g).toFixed(3)}) brightness(${(1 - 0.35 * g).toFixed(3)})` : '';
          r.e.style.borderTopColor = `rgba(221,221,240,${(0.1 * tw(t, R(i), 0.3)).toFixed(3)})`;
          const act = t >= R(i) && t < (i < N - 1 ? R(i + 1) : SUM);
          r.e.style.background = act ? 'rgba(221,221,240,.06)' : '';
        });
        expls.forEach((x, i) => P.show(x, t, R(i) + 0.9, i < N - 1 ? R(i + 1) + 0.6 : SUM - 0.3, { dy: 14, blur: 4, out: 0.25 }));
        P.show(summary, t, SUM, null, { dy: 14, blur: 4 });
        P.show(src, t, SUM + 0.4, null, { dy: 0, blur: 0 });
      },
    });
  }

  // =====================================================================================
  // 0b. FRONT — the page works without the service: your own copy, any SecNote server
  // =====================================================================================
  {
    let cap, bw, sfv, nodes, paths, pk, apil, nocode, facts, HOSTS;
    const AT = [2.0, 4.6, 7.0], NX = 1360, NY = (i) => 350 + i * 150, B = { x: 980, y: 470 };
    const active = (t) => (t < AT[0] ? -1 : t < AT[1] ? 0 : t < AT[2] ? 1 : 2);
    P.scene({
      id: 'front', dur: 12, trans: { type: 'fade', dur: 0.9 },
      build(root, S, cue) {
        HOSTS = S.front_hosts;
        cap = caption(root, S.front_title, S.front_sub);
        bw = el(root, 'div', 'bw', `<div class="bar"><div class="dots3"><i></i><i></i><i></i></div><div class="url">${P.icon('code', 18, '#4d4d58', 2.4)}${esc(S.front_url)}</div></div>`, 'left:160px;top:260px;width:820px;height:480px');
        const page = el(bw, 'div', 'abs', '', 'left:0;top:64px;width:820px;height:416px;overflow:hidden');
        const A = app(page, 0, 0, 1312, 666, S.ui);
        A.style.transformOrigin = '0 0'; A.style.transform = 'scale(.625)';
        el(A, 'div', 'hero', `<div class="tile">${P.icon('lock', 38, ACC, 2.2)}</div><h1>${esc(S.ui.hero_title)}</h1>`, 'top:120px');
        composer(A, 176, 330, 960, S.ui);
        sfv = el(bw, 'div', 'sfield', `<span>${esc(S.front_server)}</span><b></b>`).querySelector('b');
        const svg = el(root, 'div', 'links', `<svg width="1920" height="1080">${HOSTS.map(() => '<path fill="none" stroke-width="3"/>').join('')}</svg>`);
        paths = [...svg.querySelectorAll('path')];
        paths.forEach((p, i) => { p.setAttribute('d', `M${B.x} ${B.y} C ${B.x + 180} ${B.y}, ${NX - 180} ${NY(i)}, ${NX} ${NY(i)}`); p.len = p.getTotalLength(); });
        nodes = HOSTS.map((h, i) => el(root, 'div', 'node2', `<div class="ic">${P.icon('server', 24, '#cfe0ff', 2.2)}</div><span class="mono">${esc(h)}</span>`, `left:${NX}px;top:${NY(i) - 37}px`));
        pk = [0, 1].map(() => el(root, 'div', 'pk', P.icon('lock', 18, '#fff', 2.6), 'left:0;top:0'));
        apil = el(root, 'div', 'apil', `${P.icon('lock', 14, '#3ecf8e', 2.6)}${esc(S.front_api)}`);
        nocode = el(root, 'div', 'nocode', `${P.icon('x', 18, '#ff5a62', 3)}${esc(S.front_nocode)}`, 'left:1080px;top:722px');
        facts = S.front_facts.map((f, i) => el(root, 'div', 'fact', `${P.icon(['code', 'clock', 'globe', 'key'][i], 24, '#cfe0ff', 2.4)}${esc(f)}`, 'top:830px'));
        const gap = 18, wsum = () => facts.reduce((s, f) => s + f.offsetWidth, 0) + gap * (facts.length - 1);
        for (let px = 24; wsum() > 1600 && px >= 16; px--) facts.forEach((f) => { f.style.fontSize = px + 'px'; });
        let x = 960 - wsum() / 2;
        facts.forEach((f) => { f.style.left = x + 'px'; x += f.offsetWidth + gap; });
        cue(0.5, 'whoosh', { dur: 0.6 });
        nodes.forEach((_, i) => cue(1.4 + i * 0.12, 'chip', { note: ['C5', 'E5', 'G5'][i] }));
        AT.forEach((a, i) => { for (let k = 0; k < 6; k++) cue(a + k * 0.07, 'key'); cue(a + 0.5, 'ping', { note: ['E6', 'G6', 'C7'][i] }); });
        cue(3.2, 'warn');
        facts.forEach((_, i) => cue(8.6 + i * 0.15, 'pop', { note: ['G5', 'C6', 'E6', 'G6'][i], gain: 0.45 }));
      },
      update(t) {
        cap(t, 0.2);
        P.show(bw, t, 0.5, null, { dy: 40, blur: 6 });
        const a = active(t);
        nodes.forEach((n, i) => { P.pop(n, t, 1.4 + i * 0.12); n.classList.toggle('on', i === a); });
        const typed = a < 0 ? '' : `https://${HOSTS[a]}`.slice(0, Math.max(0, Math.floor((t - AT[a]) * 45)));
        set(sfv, 'textContent', typed);
        paths.forEach((p, i) => {
          const on = i === a;
          p.setAttribute('stroke', on ? 'rgba(62,207,142,.9)' : 'rgba(221,221,240,.22)');
          p.style.strokeDasharray = on ? `${p.len}` : '6 9';
          p.style.strokeDashoffset = on ? (p.len * (1 - tw(t, AT[a], 0.4, 'outCubic'))).toFixed(1) : (-t * 20).toFixed(1);
          p.style.opacity = tw(t, 1.6 + i * 0.12, 0.5);
        });
        // API traffic on the active line: one packet out, one back
        pk.forEach((k, j) => {
          if (a < 0 || t < AT[a] + 0.4) { k.style.opacity = 0; return; }
          let u = ((t - AT[a] - 0.4) * 0.7 + j * 0.5) % 1;
          if (j) u = 1 - u;
          const pt = paths[a].getPointAtLength(paths[a].len * u);
          P.xf(k, { x: pt.x, y: pt.y, o: Math.min(1, u * 8, (1 - u) * 8) });
        });
        if (a >= 0) {
          const m = paths[a].getPointAtLength(paths[a].len * 0.5);
          P.xf(apil, { x: m.x - 70, y: m.y - 46, o: tw(t, AT[a] + 0.3, 0.3) });
        } else apil.style.opacity = 0;
        P.pop(nocode, t, 3.2);
        facts.forEach((f, i) => P.pop(f, t, 8.6 + i * 0.15));
      },
    });
  }

  // =====================================================================================
  // 1. SHARE — four employees, four apps, four passwords pasted in plain text
  // =====================================================================================
  {
    let cap, wins, kept;
    const SEND = [1.2, 2.1, 3.0, 3.9];
    P.scene({
      id: 'share', dur: 9, trans: { type: 'fade', dur: 1.4 },
      build(root, S, cue) {
        this.trans.label = S.case_label;
        cap = caption(root, S.share_title, S.share_sub);
        wins = GRID.map(([x, y], i) => appWin(root, S, i, x, y, 'plain'));
        kept = wins.map((w) => {
          const c = el(root, 'div', 'chipk', `${P.icon('clock', 18, '#f5b544', 2.4)}${esc(S.kept)}`, `top:${w.y - 18}px`);
          c.style.left = w.x + W - c.offsetWidth - 24 + 'px';
          return c;
        });
        SEND.forEach((t, i) => { for (let k = 0; k < 5; k++) cue(t - 0.55 + k * 0.09, 'key'); cue(t, 'send'); cue(t + 0.05, 'pop', { note: ['A5', 'C6', 'E6', 'A6'][i], gain: 0.5 }); });
        kept.forEach((_, i) => cue(5.4 + i * 0.2, 'chip', { note: ['E5', 'G5', 'A5', 'C6'][i] }));
      },
      update(t) {
        cap(t, 0.3);
        wins.forEach((w, i) => {
          P.show(w.w, t, 0.05 + i * 0.12, null, { dy: 40, blur: 6 });
          const s0 = SEND[i], p = tw(t, s0, 0.45, 'settle');
          P.xf(w.snd, { y: 18 * (1 - p), o: clamp((t - s0) / 0.18) });
          const g = tw(t, 5.3 + i * 0.2, 0.4);
          w.val.style.background = `rgba(245,181,68,${(0.3 * g).toFixed(3)})`;
          w.val.style.boxShadow = g > 0 ? `0 0 0 2px rgba(245,181,68,${(0.75 * g).toFixed(3)})` : '';
          P.pop(kept[i], t, 5.4 + i * 0.2);
        });
      },
    });
  }

  // =====================================================================================
  // 2. LEAK — six months later one account leaks; a search over the history finds every password
  // =====================================================================================
  {
    let cap, wins, hows, at;
    const HOW = (i) => 1.8 + i * 0.16, Q = 3.7, ROW = (i) => 4.5 + i * 0.42;
    P.scene({
      id: 'leak', dur: 10, trans: { type: 'ff', dur: 1.6 },
      build(root, S, cue) {
        this.trans.label = S.later;
        cap = caption(root, S.leak_title, S.leak_sub);
        wins = GRID.map(([x, y], i) => appWin(root, S, i, x, y, 'plain'));
        hows = wins.map((w, i) => el(w.w, 'div', 'how', `${P.icon(HOWI[i], 18, '#fff', 2.6)}${esc(S.leak_how[i])}`));
        at = attacker(root, S, 'plain');
        at.ty = P.typer(at.q, [{ text: S.search_q, t0: Q, cps: 13 }], cue);
        wins.forEach((_, i) => { cue(HOW(i), 'glitch'); cue(HOW(i) + 0.05, 'warn'); });
        cue(3.0, 'whoosh', { dur: 0.8 });
        at.rows.forEach((_, i) => cue(ROW(i), 'block'));
        cue(ROW(3) + 0.35, 'impact');
      },
      update(t) {
        cap(t, 0.9);
        const shrink = tw(t, 3.0, 0.9, 'glide');
        wins.forEach((w, i) => {
          const g = clamp((t - HOW(i)) / 0.55), jit = g > 0 && g < 1 ? (P.hash(Math.floor(t * 30) * 7 + i) - 0.5) * 18 * (1 - g) : 0;
          shrinkTo(w, i, shrink, jit);
          w.red.style.opacity = t < HOW(i) ? 0 : g < 1 ? (P.hash(Math.floor(t * 24) + i * 3) > 0.4 ? 1 : 0.3) : 0.85;
          w.val.style.background = t >= HOW(i) ? '#e5484d' : '';
          w.val.style.color = t >= HOW(i) ? '#fff' : '';
          P.pop(hows[i], t, HOW(i) + 0.05);
        });
        P.show(at.a, t, 3.2, null, { dx: 90, dy: 0, blur: 8 });
        at.ty.set(t, t > 3.4);
        at.rows.forEach((r, i) => P.show(r, t, ROW(i), null, { dy: 14, blur: 4, dx: -30 }));
        at.lines(t, ROW);
        const n = at.rows.filter((_, i) => t >= ROW(i) + 0.1).length;
        set(at.cnt, 'textContent', `${n} / 4`);
        const hit = Math.max(...at.rows.map((_, i) => (t > ROW(i) + 0.1 ? Math.exp(-(t - ROW(i) - 0.1) * 7) : 0)));
        at.cnt.style.transform = `scale(${1 + 0.25 * hit})`;
        at.foot.style.boxShadow = t > ROW(3) + 0.35 ? `0 0 ${40 * Math.exp(-(t - ROW(3) - 0.35) * 2)}px rgba(255,77,88,.8)` : '';
      },
    });
  }

  // =====================================================================================
  // 3. REWIND — the same day with SecNote: the password goes into SecNote, the chats get one-time links that burn
  // =====================================================================================
  {
    let cap, bw, ty, twrap, cmp, ub, ubt, row, bub, st, dn, dots, okc, stt, prog, lt, cpb, ptr, P1, hSt, hDn, wins, burnt, boxes, ctx;
    const SEND = (i) => 6.6 + i * 0.28, READ = (i) => 8.3 + i * 0.55;
    P.scene({
      id: 'rewind', dur: 12, trans: { type: 'rw', dur: 1.6 },
      build(root, S, cue) {
        const U = S.ui;
        this.trans.label = S.rewind; this.U = U;
        cap = caption(root, S.with_title, S.with_sub);
        // SecNote at the company's own address
        bw = el(root, 'div', 'bw', `<div class="bar"><div class="dots3"><i></i><i></i><i></i></div><div class="url">${P.icon('lock', 18, '#18a566', 2.6)}https://${esc(S.org_host)}</div></div>`, 'left:360px;top:250px;width:1200px;height:700px;transform-origin:50% 50%');
        const A = app(bw, 0, 64, 1200, 636, U);
        cmp = composer(A, 120, 474, 960, U);
        twrap = el(cmp.ct, 'span');
        const note = `${S.apps[0].label} ${S.secrets[0]}`;
        ty = P.typer(twrap, [{ text: note, t0: 1.3, cps: 30 }], cue);
        ub = el(A, 'div', 'ubub', `<span>${esc(note)}</span>`, 'right:120px;top:96px'); ubt = ub.firstChild;
        row = el(A, 'div', 'brow', ava() + '<div class="bubble"><div class="st"></div><div class="dn"></div></div>', 'left:120px;top:176px;width:880px');
        bub = row.querySelector('.bubble'); st = row.querySelector('.st'); dn = row.querySelector('.dn');
        st.innerHTML = `<div class="typing"><span class="dots"><i></i><i></i><i></i></span><span class="okc">${P.icon('check', 26, '#18a566', 3)}</span><span class="tt"></span><span class="prog"></span></div>`;
        dots = [...st.querySelectorAll('.dots i')]; okc = st.querySelector('.okc'); stt = st.querySelector('.tt'); prog = st.querySelector('.prog');
        dn.innerHTML = `<div>${esc(U.link_ready)}</div><div class="linkbox"><span class="lt">${esc(link(S, 0))}&amp;pin=${esc(S.pin)}<span class="k">#${esc(S.key)}</span></span></div>` +
          `<div class="acts"><span class="sbtn prim cp">${esc(U.link_copy)}</span><span class="sbtn">${esc(U.link_qr)}</span></div>`;
        lt = dn.querySelector('.lt'); cpb = dn.querySelector('.cp');
        st.style.display = 'none'; hDn = bub.offsetHeight;
        const r = P.rect(cpb); P1 = { x: r.cx, y: r.cy + 4 };
        dn.style.display = 'none'; st.style.display = ''; stt.textContent = U.status_checking; hSt = bub.offsetHeight;
        ptr = P.pointer(root);
        // then the four apps, now with links
        wins = GRID.map(([x, y], i) => appWin(root, S, i, x, y, 'link'));
        boxes = wins.map((w) => { const b = P.rect(w.val); return { x: b.x, y: b.y, w: b.w, h: b.h }; });
        burnt = wins.map((w, i) => {
          const c = el(root, 'div', 'burnt', `${P.icon('flame', 18, '#3ecf8e', 2.4)}${esc(S.burned)}`, `top:${w.y - 18}px`);
          c.style.left = w.x + W - c.offsetWidth - 24 + 'px';
          return c;
        });
        ctx = canvas(root);
        cue(2.45, 'enter'); cue(2.5, 'send');
        for (let i = 0; i < 4; i++) cue(2.75 + i * 0.2, 'tick');
        cue(3.6, 'ping', { note: 'E6' }); cue(4.0, 'chime', { notes: ['C6', 'E6', 'G6'] }); cue(5.2, 'click');
        cue(5.8, 'whoosh', { dur: 0.7 });
        wins.forEach((_, i) => { cue(SEND(i), 'send'); cue(SEND(i) + 0.05, 'pop', { note: ['C6', 'E6', 'G6', 'C7'][i], gain: 0.45 }); cue(READ(i), 'burn', { dur: 0.7 }); cue(READ(i) + 0.3, 'chip', { note: ['G5', 'C6', 'E6', 'G6'][i] }); });
      },
      update(t) {
        const U = this.U;
        cap(t, 0.6);
        ctx.clearRect(0, 0, 1920, 1080);
        // SecNote window: type, Enter, proof-of-work, link, copy; then it hands over to the four apps
        const out = tw(t, 5.8, 0.6, 'inOutCubic');
        P.xf(bw, { y: 40 * (1 - tw(t, 0.5, 0.7, 'settle')), s: 1 - 0.12 * out, o: clamp((t - 0.5) / 0.3) * (1 - out) });
        const typing = t >= 1.25 && t < 2.5;
        twrap.style.display = typing ? '' : 'none';
        cmp.ph.style.display = typing ? 'none' : '';
        ty.set(t, typing);
        cmp.send.style.background = typing && t > 1.35 ? ACC : '';
        P.xf(ub, { y: 24 * (1 - tw(t, 2.5, 0.4, 'settle')), o: clamp((t - 2.5) / 0.2) });
        const bl = 6 * tw(t, 2.85, 0.3);
        ubt.style.filter = bl > 0.05 ? `blur(${bl.toFixed(2)}px)` : '';
        P.xf(row, { y: 20 * (1 - tw(t, 2.7, 0.4, 'settle')), o: clamp((t - 2.7) / 0.2) });
        const done = t >= 4.0;
        st.style.display = done ? 'none' : ''; dn.style.display = done ? '' : 'none';
        if (!done) {
          const ok = t >= 3.6;
          set(stt, 'textContent', ok ? U.status_human : U.status_checking);
          st.firstChild.classList.toggle('ok', ok);
          okc.style.display = ok ? '' : 'none'; dots[0].parentNode.style.display = ok ? 'none' : '';
          dotsAt(dots, t);
          const n = t < 2.75 ? 0 : Math.min(4, 1 + Math.floor((t - 2.75) / 0.2));
          set(prog, 'textContent', !ok && n ? `${n}/4` : '');
          bub.style.height = hSt + 'px';
        } else {
          bub.style.height = lerp(hSt, hDn, tw(t, 4.0, 0.3, 'outCubic')).toFixed(1) + 'px';
          P.show(dn, t, 4.0, null, { dy: 10, blur: 3 });
          lt.style.filter = 'blur(6px)';
          set(cpb, 'textContent', t >= 5.2 ? U.link_copied : U.link_copy);
          cpb.style.transform = t > 5.12 && t < 5.28 ? 'scale(.95)' : '';
        }
        const pp = P.arc({ x: 1500, y: 1060 }, P1, -50, tw(t, 4.4, 0.7, 'glide'));
        ptr.set(pp.x, pp.y, clamp((t - 4.35) / 0.2) * (1 - out), t > 5.1 && t < 5.28 ? 1 : 0, t >= 5.2 ? t - 5.2 : -1);
        // the four apps: links go out, each is opened once and burns
        wins.forEach((w, i) => {
          P.show(w.w, t, 6.0 + i * 0.1, null, { dy: 40, blur: 6, s: 0.96 });
          const p = tw(t, SEND(i), 0.45, 'settle');
          P.xf(w.snd, { y: 18 * (1 - p), o: clamp((t - SEND(i)) / 0.18) });
          const rd = tw(t, READ(i) + 0.2, 0.4);
          w.val.style.color = rd > 0 ? `rgba(${Math.round(lerp(37, 150, rd))},${Math.round(lerp(99, 155, rd))},${Math.round(lerp(235, 170, rd))},1)` : '';
          w.val.style.textDecorationColor = rd > 0 ? `rgba(150,155,170,${rd})` : '';
          embers(ctx, boxes[i], (t - READ(i)) / 0.9, 300 + i * 70);
          P.pop(burnt[i], t, READ(i) + 0.3);
        });
      },
    });
  }

  // =====================================================================================
  // 4. LEAK AGAIN — six months later, the same leak; the search finds only dead links
  // =====================================================================================
  {
    let cap, wins, hows, at, gone, ptr, P0;
    const HOW = (i) => 1.6 + i * 0.12, Q = 3.1, ROW = (i) => 3.75 + i * 0.3, CLICK = 5.15;
    P.scene({
      id: 'leak2', dur: 8, trans: { type: 'ff', dur: 1.6 },
      build(root, S, cue) {
        const U = S.ui;
        this.trans.label = S.later;
        cap = caption(root, S.leak2_title, S.leak2_sub);
        wins = GRID.map(([x, y], i) => appWin(root, S, i, x, y, 'link'));
        wins.forEach((w) => { w.val.style.color = '#969baa'; w.val.style.textDecorationColor = '#969baa'; });
        hows = wins.map((w, i) => el(w.w, 'div', 'how', `${P.icon(HOWI[i], 18, '#fff', 2.6)}${esc(S.leak_how[i])}`));
        at = attacker(root, S, 'link');
        at.ty = P.typer(at.q, [{ text: S.search_q, t0: Q, cps: 13 }], cue);
        const d = P.rect(at.rows[0].querySelector('.dead')); P0 = { x: d.x + 120, y: d.cy + 4 };
        gone = el(root, 'div', 'gonec', `${ava()}<div><h3>${esc(U.burned_title)}</h3><p>${esc(U.burned_sub)}</p></div>`);
        ptr = P.pointer(root);
        wins.forEach((_, i) => cue(HOW(i), 'glitch'));
        cue(2.4, 'whoosh', { dur: 0.8 });
        at.rows.forEach((_, i) => cue(ROW(i), 'pop', { note: ['E5', 'D5', 'C5', 'A4'][i], gain: 0.5 }));
        cue(CLICK, 'click'); cue(CLICK + 0.25, 'gone'); cue(CLICK + 0.75, 'chime', { notes: ['C6', 'E6', 'G6', 'C7'] });
      },
      update(t) {
        cap(t, 0.9);
        const shrink = tw(t, 2.4, 0.9, 'glide');
        wins.forEach((w, i) => {
          const g = clamp((t - HOW(i)) / 0.5), jit = g > 0 && g < 1 ? (P.hash(Math.floor(t * 30) * 7 + i) - 0.5) * 16 * (1 - g) : 0;
          shrinkTo(w, i, shrink, jit);
          w.red.style.opacity = t < HOW(i) ? 0 : g < 1 ? (P.hash(Math.floor(t * 24) + i * 3) > 0.4 ? 1 : 0.3) : 0.6;
          P.pop(hows[i], t, HOW(i) + 0.05);
        });
        P.show(at.a, t, 2.6, null, { dx: 90, dy: 0, blur: 8 });
        at.ty.set(t, t > 2.9);
        at.rows.forEach((r, i) => P.show(r, t, ROW(i), null, { dy: 14, blur: 4, dx: -30 }));
        at.lines(t, ROW);
        // the attacker opens a link: the note is already gone
        const pp = P.arc({ x: 1700, y: 1060 }, P0, -40, tw(t, 4.4, 0.65, 'glide'));
        ptr.set(pp.x, pp.y, clamp((t - 4.35) / 0.2) * (1 - tw(t, 6.0, 0.3)), t > CLICK - 0.08 && t < CLICK + 0.1 ? 1 : 0, t >= CLICK ? t - CLICK : -1);
        P.show(gone, t, CLICK + 0.2, null, { dy: 24, blur: 4 });
        const ok = t >= CLICK + 0.75;
        at.foot.className = 'foot' + (ok ? ' ok' : '');
        set(at.cnt, 'textContent', '0 / 4');
        at.cnt.style.transform = ok ? `scale(${1 + 0.25 * Math.exp(-(t - CLICK - 0.75) * 6)})` : '';
        at.foot.style.boxShadow = ok ? `0 0 ${40 * Math.exp(-(t - CLICK - 0.75) * 2)}px rgba(62,207,142,.8)` : '';
      },
    });
  }

  // =====================================================================================
  // 4b. USES — more everyday cases: onboarding, partners, files, in person
  // =====================================================================================
  {
    let cap, cards, tys, att, qr, scan, phone;
    const U = (i) => 0.8 + i * 3.2;
    P.scene({
      id: 'uses', dur: 14, trans: { type: 'fade', dur: 0.9 },
      build(root, S, cue) {
        const X = S.uses;
        cap = caption(root, S.uses_title, S.uses_sub);
        cards = X.map((u, i) => {
          const [x, y] = GRID[i];
          const c = el(root, 'div', 'ucard', `<div class="uh"><div class="ic">${P.icon(['mail', 'users', 'clip', 'qr'][i], 28, '#cfe0ff', 2.2)}</div>${esc(u.title)}</div><div class="ud">${esc(u.desc)}</div>`, `left:${x}px;top:${y}px`);
          P.fit(c.querySelector('.ud'), 704, 21, 16, 58);
          return c;
        });
        const m1 = el(cards[0], 'div', 'umock', `<small>${esc(X[0].from)} &lt;${esc(X[0].addr)}&gt; · to sam@acme.corp</small><div>${esc(X[0].msg)}</div><span class="lnk t"></span>`);
        const m2 = el(cards[1], 'div', 'umock', `<small>${esc(X[1].who)}</small><div class="bo">${esc(X[1].msg)}<br><span class="lnk t"></span></div>`);
        const m3 = el(cards[2], 'div', 'umock', `<div class="att">${P.icon('clip', 18, '#4d4d58', 2.2)}${esc(X[2].file)} <small>${esc(X[2].size)}</small></div><div style="margin-top:10px">${esc(X[2].msg)}: <span class="lnk t"></span></div>`);
        att = m3.querySelector('.att');
        tys = [m1, m2, m3].map((m, i) => P.typer(m.querySelector('.t'), [{ text: link(S, i, true), t0: U(i) + 1.0, cps: 45 }], () => {}));
        phone = el(cards[3], 'div', 'uphone', `${P.icon('phone', 46, '#cfe0ff', 1.8)}<span>${esc(X[3].msg)}</span>`);
        qr = el(cards[3], 'div', 'uqr');
        try { qr.appendChild(QRCode({ msg: `${link(S, 3)}&pin=${S.pin}#${S.key}`, dim: 124, pad: 1, ecl: 'M' })); } catch (e) { /* QR is decoration */ }
        scan = el(qr, 'div', 'scan', '', 'top:0');
        X.forEach((_, i) => { cue(U(i), 'whoosh', { dur: 0.5 }); cue(U(i) + 0.3, 'pop', { note: ['C5', 'E5', 'G5', 'C6'][i], gain: 0.5 }); });
        [0, 1, 2].forEach((i) => { for (let k = 0; k < 6; k++) cue(U(i) + 1.0 + k * 0.08, 'key'); });
        cue(U(2) + 0.6, 'pop', { note: 'A5', gain: 0.4 });
        cue(U(3) + 0.7, 'digital', { dur: 0.4 }); cue(U(3) + 2.3, 'ping', { note: 'G6' });
      },
      update(t) {
        cap(t, 0.2);
        cards.forEach((c, i) => P.show(c, t, U(i), null, { dy: 50, blur: 6, s: 0.96 }));
        tys.forEach((ty) => ty.set(t, false));
        P.pop(att, t, U(2) + 0.6);
        P.show(phone, t, U(3) + 0.5, null, { dx: -20, dy: 0, blur: 3 });
        const q = tw(t, U(3) + 0.7, 0.5, 'settle');
        P.xf(qr, { o: clamp((t - U(3) - 0.7) / 0.2), s: 0.6 + 0.4 * q });
        const sp = (t - U(3) - 1.3) / 1.0;
        scan.style.top = (clamp(sp) * 136).toFixed(1) + 'px';
        scan.style.opacity = sp > 0 && sp < 1 ? 1 : 0;
      },
    });
  }

  // =====================================================================================
  // 4c. AGENTS — discovery files and the WebMCP tool: an AI agent hands over a one-time link
  // =====================================================================================
  {
    let cap, panel, ub, tool, spin, okc, ab, ty, disc, rows, note;
    P.scene({
      id: 'agents', dur: 10, trans: { type: 'fade', dur: 0.9 },
      build(root, S, cue) {
        cap = caption(root, S.agent_title, S.agent_sub);
        panel = el(root, 'div', 'agent', `<div class="agh">${P.icon('spark', 24, ACC, 2)}${esc(S.agent_head)}</div>`, 'left:160px;top:260px;width:900px;height:470px');
        ub = el(panel, 'div', 'agu', esc(S.agent_ask));
        tool = el(panel, 'div', 'agt', `<span class="sp"></span><span class="ok">${P.icon('check', 20, '#18a566', 3)}</span><b>${esc(S.agent_tool)}</b><small>${esc(S.agent_tool_via)}</small>`);
        spin = tool.querySelector('.sp'); okc = tool.querySelector('.ok');
        ab = el(panel, 'div', 'aga', `${esc(S.agent_done)}<br><span class="lnk"></span>`);
        ty = P.typer(ab.querySelector('.lnk'), [{ text: link(S, 0, true), t0: 4.7, cps: 50 }], () => {});
        disc = el(root, 'div', 'disc', `<div class="dh">${P.icon('search', 20, '#cfe0ff', 2.4)}${esc(S.agent_disc)}</div>`, 'left:1110px;top:260px;width:650px;height:470px');
        rows = S.agent_files.map(([f, d]) => el(disc, 'div', 'drow', `<div class="dc">${P.icon('check', 16, '#3ecf8e', 3)}</div><div style="min-width:0"><div class="df">${esc(f)}</div><div class="dd">${esc(d)}</div></div>`));
        rows.forEach((r) => { const f = r.querySelector('.df'); f.style.display = 'inline-block'; P.fit(f, 540, 19, 14); });
        note = el(disc, 'div', 'dnote', esc(S.agent_note));
        cue(0.4, 'whoosh', { dur: 0.6 }); cue(0.9, 'send');
        rows.forEach((_, i) => cue(1.6 + i * 0.3, 'check', { i }));
        cue(3.0, 'pop', { note: 'C5', gain: 0.5 }); cue(3.0, 'digital', { dur: 0.9 }); cue(4.0, 'ping', { note: 'E6' });
        cue(4.4, 'chime', { notes: ['C6', 'E6', 'G6'] });
      },
      update(t) {
        cap(t, 0.2);
        P.show(panel, t, 0.4, null, { dy: 40, blur: 6 });
        P.show(disc, t, 0.6, null, { dy: 40, blur: 6 });
        P.show(ub, t, 0.9, null, { dy: 16, blur: 3 });
        rows.forEach((r, i) => P.show(r, t, 1.6 + i * 0.3, null, { dx: 24, dy: 0, blur: 3 }));
        P.show(tool, t, 3.0, null, { dy: 16, blur: 3 });
        const done = t >= 4.0;
        spin.style.display = done ? 'none' : ''; okc.style.display = done ? 'grid' : 'none';
        spin.style.transform = `rotate(${(t * 480).toFixed(0)}deg)`;
        P.show(ab, t, 4.3, null, { dy: 16, blur: 3 });
        ty.set(t, false);
        P.show(note, t, 5.6, null, { dy: 0, blur: 0 });
      },
    });
  }

  // =====================================================================================
  // 5. ADMIN — one install on the company domain covers every app, because a link works everywhere
  // =====================================================================================
  {
    let cap, term, ty, srv, sst, arrow, spokes, nodes, pks, facts;
    const SRV = { x: 1010, y: 560 }, NX = 1350, NY = (i) => 268 + i * 118;
    P.scene({
      id: 'admin', dur: 10, trans: { type: 'fade', dur: 0.9 },
      build(root, S, cue) {
        cap = caption(root, S.admin_title, S.admin_sub);
        term = el(root, 'div', 'term', `<div class="tb"><div class="dots3"><i></i><i></i><i></i></div>${P.icon('term', 20, '#a6a6c4', 2)}${esc(S.admin_term)}</div><div class="tx"></div>`, 'left:160px;top:300px;width:640px;height:300px');
        const c1 = 'docker build -t secnote \\\n    https://github.com/pwn-all/secure-notes.git\n';
        const c2 = `docker run -d --env-file .env.production \\\n    -p 80:80 -p 443:443 \\\n    -e DOMAIN=${S.org_host} \\\n    -e EMAIL=${S.org_mail} secnote`;
        ty = P.typer(term.querySelector('.tx'), [{ text: '$ ', cls: 'pr', t0: 0.4 }, { text: c1, t0: 0.5, cps: 75 }, { text: '$ ', cls: 'pr', t0: 1.6 }, { text: c2, t0: 1.7, cps: 95 }], () => {});
        for (let t = 0.5; t < 2.9; t += 0.07) cue(t, 'key');
        cue(1.5, 'enter'); cue(3.0, 'enter');
        // the company server
        srv = el(root, 'div', 'srv', `<div style="display:flex;justify-content:center">${LOCK(78, '#ddddf0')}</div><div class="host">${esc(S.org_host)}</div><div class="st"><i></i><span></span></div>`);
        srv.style.left = SRV.x - 165 + 'px'; srv.style.top = SRV.y - srv.offsetHeight / 2 + 'px';
        sst = srv.querySelector('.st span'); sst.textContent = `${S.ui.online} · ${S.admin_server}`;
        const svg = el(root, 'div', 'links', `<svg width="1920" height="1080"><path class="ar" fill="none" stroke="rgba(221,221,240,.5)" stroke-width="3" stroke-dasharray="8 8"/>${S.admin_apps.map(() => '<path class="sp" fill="none" stroke="rgba(110,143,192,.75)" stroke-width="3"/>').join('')}</svg>`);
        arrow = svg.querySelector('.ar');
        arrow.setAttribute('d', `M800 450 C 840 450, 820 ${SRV.y}, ${SRV.x - 165} ${SRV.y}`);
        spokes = [...svg.querySelectorAll('.sp')];
        nodes = S.admin_apps.map((n, i) => el(root, 'div', 'node2', `<div class="ic">${P.icon(['chat', 'phone', 'mail', 'ticket', 'apps'][i], 24, '#cfe0ff', 2.2)}</div>${esc(n)}`, `left:${NX}px;top:${NY(i) - 37}px`));
        spokes.forEach((p, i) => { p.setAttribute('d', `M${SRV.x + 165} ${SRV.y} C ${SRV.x + 260} ${SRV.y}, ${NX - 100} ${NY(i)}, ${NX} ${NY(i)}`); p.len = p.getTotalLength(); p.style.strokeDasharray = p.len; });
        pks = S.admin_apps.map(() => el(root, 'div', 'pk', P.icon('lock', 18, '#fff', 2.6), 'left:0;top:0'));
        facts = S.admin_facts.map((f, i) => el(root, 'div', 'fact', `${P.icon(['lock', 'chip', 'user', 'code'][i], 24, '#cfe0ff', 2.4)}${esc(f)}`));
        const gap = 20;
        [[0, 1], [2, 3]].forEach((ix, r) => {
          const rowEls = ix.map((i) => facts[i]).filter(Boolean);
          const wsum = () => rowEls.reduce((s, f) => s + f.offsetWidth, 0) + gap * (rowEls.length - 1);
          for (let px = 24; wsum() > 1600 && px >= 16; px--) rowEls.forEach((f) => { f.style.fontSize = px + 'px'; });
          let x = 960 - wsum() / 2;
          rowEls.forEach((f) => { f.style.left = x + 'px'; f.style.top = 868 + r * 76 + 'px'; x += f.offsetWidth + gap; });
        });
        cue(3.2, 'lock'); cue(3.3, 'ping', { note: 'G6' }); cue(3.6, 'whoosh', { dur: 0.7 });
        nodes.forEach((_, i) => cue(3.9 + i * 0.12, 'chip', { note: ['C5', 'E5', 'G5', 'C6', 'E6'][i] }));
        facts.forEach((_, i) => cue(5.6 + i * 0.18, 'pop', { note: ['G5', 'C6', 'E6', 'G6'][i], gain: 0.45 }));
      },
      update(t) {
        cap(t, 0.3);
        P.show(term, t, 0.1, null, { dy: 40, blur: 6 });
        ty.set(t, true);
        arrow.style.strokeDashoffset = -t * 30;
        arrow.style.opacity = tw(t, 3.0, 0.3);
        const on = tw(t, 3.2, 0.5, 'settle');
        P.xf(srv, { s: 0.6 + 0.4 * on, o: clamp((t - 3.1) / 0.2) });
        srv.style.boxShadow = t > 3.2 ? `0 30px 80px rgba(0,0,0,.5), 0 0 ${80 + 60 * Math.exp(-(t - 3.2) * 3)}px rgba(110,143,192,${0.35 + 0.4 * Math.exp(-(t - 3.2) * 3)})` : '';
        spokes.forEach((p, i) => { p.style.strokeDashoffset = p.len * (1 - tw(t, 3.6 + i * 0.08, 0.5, 'outCubic')); });
        nodes.forEach((n, i) => P.pop(n, t, 3.9 + i * 0.12));
        // one-time links travelling to every app
        pks.forEach((k, i) => {
          const u = t < 4.6 ? -1 : ((t - 4.6) * 0.55 + i * 0.37) % 1;
          if (u < 0) { k.style.opacity = 0; return; }
          const pt = spokes[i].getPointAtLength(spokes[i].len * u);
          P.xf(k, { x: pt.x, y: pt.y, o: Math.min(1, u * 8, (1 - u) * 8) });
        });
        facts.forEach((f, i) => P.pop(f, t, 5.6 + i * 0.18));
      },
    });
  }

  // =====================================================================================
  // 6. OUTRO — the og.svg composition: lock, monospaced name, squiggle, promise, badges, address
  // =====================================================================================
  {
    let glow, lock, shk, name, sq, tag, sub, badges, url, NAME;
    P.scene({
      id: 'outro', dur: 6, trans: { type: 'fade', dur: 0.9 },
      build(root, S, cue) {
        NAME = 'SecNote';
        glow = el(root, 'div', 'glow', '', 'left:660px;top:-40px;width:600px;height:600px');
        lock = el(root, 'div', 'abs', LOCK(150, '#ddddf0'), `left:${960 - 150 * 50 / 59 / 2}px;top:150px;transform-origin:50% 60%`);
        shk = lock.querySelector('.shk');
        name = el(root, 'div', 'oname', '', 'top:350px');
        let d = 'M660 505';
        for (let x = 660, k = 0; x < 1260; x += 22, k++) d += ` Q${x + 11} ${505 + (k % 2 ? 7 : -7)} ${x + 22} 505`;
        const sv = el(root, 'div', 'links', `<svg width="1920" height="1080"><path d="${d}" fill="none" stroke="#6e8fc0" stroke-width="3.5" stroke-linecap="round"/></svg>`);
        sq = sv.querySelector('path'); sq.len = sq.getTotalLength(); sq.style.strokeDasharray = sq.len;
        tag = el(root, 'div', 'lead', esc(S.outro_tag), 'top:560px;font-weight:800;color:#fff');
        P.fit(tag, 1600, 54, 30, 140);
        sub = el(root, 'div', 'lead', esc(S.outro_sub), 'top:642px');
        P.fit(sub, 1600, 32, 22, 90);
        badges = el(root, 'div', 'badges', S.outro_badges.map((b) => `<span>${esc(b)}</span>`).join(''), 'top:730px');
        url = el(root, 'div', 'url', esc(S.outro_url), 'top:840px');
        for (let i = 0; i < NAME.length; i++) cue(0.45 + i * 0.08, 'key');
        cue(0.85, 'lock'); cue(0.9, 'chime', { notes: ['E5', 'G5', 'C6', 'E6'] });
        [...badges.children].forEach((_, i) => cue(2.3 + i * 0.12, 'pop', { note: ['G5', 'C6', 'E6', 'G6'][i], gain: 0.4 }));
      },
      update(t) {
        const a = tw(t, 0.1, 0.6, 'settle'), click = tw(t, 0.85, 0.12, 'inCubic');
        P.xf(lock, { y: 30 * (1 - a), o: clamp((t - 0.1) / 0.3) });
        shk.setAttribute('transform', `translate(0 ${(-6 * (1 - click)).toFixed(2)})`);
        P.xf(glow, { o: 0.3 + 0.5 * tw(t, 0.85, 0.5) + 0.05 * Math.sin(t * 2.4), s: 0.9 + 0.1 * tw(t, 0.85, 0.5) });
        const n = clamp(Math.floor((t - 0.4) / 0.08) + 1, 0, NAME.length);
        set(name, 'innerHTML', `${esc(NAME.slice(0, n))}<span style="opacity:0">${esc(NAME.slice(n))}</span>`);
        sq.style.strokeDashoffset = sq.len * (1 - tw(t, 1.0, 0.7, 'inOutSine'));
        P.show(tag, t, 1.5);
        P.show(sub, t, 1.9);
        [...badges.children].forEach((b, i) => P.pop(b, t, 2.3 + i * 0.12));
        P.show(url, t, 2.8);
      },
    });
  }
})();
