// Sound track: synthesised music (120 BPM; C major comparison, A/D minor leak, C major with SecNote) and sound effects, rendered offline with Web Audio.
// Every effect comes from a scene cue (P.cues), so picture and sound stay in sync by construction; noise is seeded,
// so the same film always gives the same WAV. The render tool normalises loudness to -14 LUFS with ffmpeg.
(function () {
  'use strict';
  const P = window.P, SR = 48000;
  const hz = (m) => 440 * 2 ** ((m - 69) / 12);
  const NOTE = (n) => {
    const m = /^([A-G])(#|b)?(\d)$/.exec(n);
    return hz({ C: 0, D: 2, E: 4, F: 5, G: 7, A: 9, B: 11 }[m[1]] + (m[2] === '#' ? 1 : m[2] === 'b' ? -1 : 0) + (+m[3] + 1) * 12);
  };

  function score(ctx) {
    const rnd = P.rng(4242), END = P.total;
    const at = (id) => P.info(id).start;
    // sections: an everyday groove, the leak (dark), tape rewind, with SecNote (bright), the second leak (held back, then
    // resolved), the admin (full), the outro. Bars are 2 s (120 BPM) on a grid that starts at 1 s.
    const T = { share: at('share'), uses: at('uses'), leak: at('leak'), rw: at('rewind'), with: at('rewind') + 2, leak2: at('leak2'), calm: at('leak2') + 5.9, admin: at('admin'), outro: at('outro') };

    // ----- buses -----
    const noise = ctx.createBuffer(1, SR * 2, SR);
    noise.getChannelData(0).forEach((_, i, d) => { d[i] = rnd() * 2 - 1; });
    const ir = ctx.createBuffer(2, SR * 2.6, SR);
    for (let c = 0; c < 2; c++) ir.getChannelData(c).forEach((_, i, d) => { d[i] = (rnd() * 2 - 1) * (1 - i / d.length) ** 3.4; });
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.value = -16; comp.knee.value = 8; comp.ratio.value = 3.5; comp.attack.value = 0.004; comp.release.value = 0.2;
    const master = ctx.createGain(); master.connect(comp); comp.connect(ctx.destination);
    master.gain.setValueAtTime(1, 0); master.gain.setValueAtTime(1, END - 1.6); master.gain.linearRampToValueAtTime(0, END);
    const verb = ctx.createConvolver(); verb.buffer = ir;
    const verbOut = ctx.createGain(); verbOut.gain.value = 0.3; verb.connect(verbOut); verbOut.connect(master);
    const send = (node, amount) => { const g = ctx.createGain(); g.gain.value = amount; node.connect(g); g.connect(verb); };
    const music = ctx.createGain(); music.connect(master);
    const lv = [[0, 0.7], [T.share - 0.8, 0.7], [T.share - 0.1, 0.35], [T.share + 0.6, 0.75], [T.leak - 0.6, 0.75], [T.leak + 0.2, 0.25], [T.leak + 1.4, 0.8], [T.rw - 0.5, 0.8], [T.rw, 0], [T.with - 0.05, 0], [T.with, 0.85],
      [T.leak2 - 0.6, 0.85], [T.leak2 + 0.2, 0.3], [T.leak2 + 1.4, 0.65], [T.calm, 0.7], [T.calm + 0.3, 0.9], [T.admin, 0.9], [T.outro, 1]];
    music.gain.setValueAtTime(lv[0][1], 0);
    lv.forEach(([t, v]) => music.gain.linearRampToValueAtTime(v, t));
    const pump = ctx.createGain(); pump.connect(music);
    const fx = ctx.createGain(); fx.gain.value = 1; fx.connect(master); send(fx, 0.18);

    // ----- tiny synth kit -----
    const g = (dest, t, peak, a, decay, hold = 0) => {
      const n = ctx.createGain(); n.gain.setValueAtTime(0, t); n.gain.linearRampToValueAtTime(peak, t + a);
      n.gain.setValueAtTime(peak, t + a + hold); n.gain.exponentialRampToValueAtTime(0.0001, t + a + hold + decay); n.connect(dest); return n;
    };
    const osc = (type, f, t, len, dest, f2, glide) => {
      const o = ctx.createOscillator(); o.type = type; o.frequency.setValueAtTime(f, t);
      if (f2) o.frequency.exponentialRampToValueAtTime(f2, t + (glide || len)); o.connect(dest); o.start(t); o.stop(t + len + 0.05); return o;
    };
    const filt = (type, f, q, dest) => { const b = ctx.createBiquadFilter(); b.type = type; b.frequency.value = f; b.Q.value = q || 0.7; b.connect(dest); return b; };
    const hiss = (t, len, dest) => { const s = ctx.createBufferSource(); s.buffer = noise; s.loop = true; s.connect(dest); s.start(t, rnd() * 1.5); s.stop(t + len + 0.05); return s; };
    const bell = (t, f, peak, dest, decay = 1.4) => {
      osc('sine', f, t, decay, g(dest, t, peak, 0.004, decay));
      osc('sine', f * 2, t, decay * 0.4, g(dest, t, peak * 0.3, 0.004, decay * 0.4));
      osc('sine', f * 3.01, t, decay * 0.2, g(dest, t, peak * 0.12, 0.002, decay * 0.2));
    };

    // ----- music -----
    const padBus = filt('lowpass', 1800, 0.6, pump); send(padBus, 0.35);
    const bassBus = filt('lowpass', 380, 0.8, pump);
    const arpF = filt('lowpass', 1200, 4, pump); send(arpF, 0.25);
    const delay = ctx.createDelay(1); delay.delayTime.value = 0.375; const fb = ctx.createGain(); fb.gain.value = 0.3;
    const dl = filt('lowpass', 2500, 0.7, pump); delay.connect(fb); fb.connect(delay); delay.connect(dl);
    const arpIn = ctx.createGain(); arpIn.connect(arpF); const ds = ctx.createGain(); ds.gain.value = 0.35; arpIn.connect(ds); ds.connect(delay);
    const drums = ctx.createGain(); drums.gain.value = 0.9; drums.connect(music);
    // brightness per section
    [[0, 2200, 1800], [T.share, 1300, 900], [T.leak, 700, 500], [T.with, 2600, 2400], [T.leak2 + 0.5, 900, 700], [T.calm, 2800, 3200], [T.admin, 3000, 3600], [T.outro, 3200, 3000]]
      .forEach(([t, p, a]) => { padBus.frequency.setTargetAtTime(p, t, 0.25); arpF.frequency.setTargetAtTime(a, t, 0.25); });

    const AM = [57, 60, 64], F = [53, 57, 60], C = [55, 60, 64], G = [55, 59, 62], DM = [50, 53, 57], BB = [50, 53, 58], A_ = [49, 52, 57];
    const section = (t) => (t < T.share ? 'cmp' : t < T.leak ? 'day' : t < T.rw ? 'leak' : t < T.with ? 'rw' : t < T.leak2 ? 'with' : t < T.calm ? 'leak2' : t < T.outro ? 'up' : 'outro');
    const PROG = { cmp: [[C, 48], [AM, 45], [F, 41], [G, 43]], day: [[AM, 45], [F, 41], [C, 48], [G, 43]], leak: [[DM, 38], [BB, 34], [DM, 38], [A_, 33]], with: [[C, 48], [G, 43], [AM, 45], [F, 41]], leak2: [[AM, 45], [F, 41]], up: [[C, 48], [G, 43], [AM, 45], [F, 41]] };
    const pad = (notes, t, len, peak) => notes.forEach((m) => [-7, 7].forEach((det) => {
      const o = osc('sawtooth', hz(m), t, len + 1, g(padBus, t, peak, 0.3, 0.9, Math.max(0, len - 0.3)));
      o.detune.value = det;
    }));
    const counters = {};
    for (let t = 1; t < T.outro - 0.01; t += 2) {
      const sec = section(t);
      if (sec === 'rw') continue;
      const k = (counters[sec] = (counters[sec] || 0) + 1) - 1, [chord, root] = PROG[sec][k % PROG[sec].length];
      const len = Math.min(2, T.outro - t);
      pad(chord, t, len, sec === 'leak' ? 0.05 : 0.04);
      const busy = sec === 'with' || sec === 'up' || (sec === 'leak' && t >= T.leak + 3);
      if (busy) for (let s = 0; s < len / 0.25 - 0.01; s++) {
        const tt = t + s * 0.25, m = root + (sec === 'leak' ? 0 : [0, 0, 12, 0, 0, 12, 0, 7][s % 8]);
        osc('sawtooth', hz(m), tt, 0.22, g(bassBus, tt, sec === 'leak' ? 0.26 : 0.22, 0.005, 0.2));
        osc('sine', hz(m - 12), tt, 0.22, g(bassBus, tt, 0.25, 0.005, 0.2));
      } else {
        osc('sawtooth', hz(root), t, len, g(bassBus, t, 0.1, 0.02, 0.6, Math.max(0, len - 0.6)));
        osc('sine', hz(root - 12), t, len, g(bassBus, t, 0.12, 0.02, 0.6, Math.max(0, len - 0.6)));
      }
      if (sec === 'cmp' || sec === 'day' || sec === 'with' || sec === 'up' || sec === 'leak2') {
        const tones = [...chord.map((m) => m + 12), chord[0] + 24];
        for (let s = 0; s < len / 0.125 - 0.01; s++) {
          const tt = t + s * 0.125, m = tones[[0, 1, 2, 3, 2, 1, 2, 3][s % 8]];
          osc('square', hz(m), tt, 0.12, g(arpIn, tt, sec === 'day' ? 0.03 : sec === 'cmp' ? 0.035 : 0.05, 0.003, 0.11));
        }
      }
    }
    // ending: F, G, then C to the end
    [[T.outro, 2, F, 41], [T.outro + 2, 1.5, G, 43], [T.outro + 3.5, END - T.outro - 3.5, [48, 55, 60, 64, 67], 36]].forEach(([t, len, ch, root], i) => {
      pad(ch, t, len, i === 2 ? 0.06 : 0.045);
      osc('sawtooth', hz(root), t, len, g(bassBus, t, 0.11, 0.02, 0.6, Math.max(0, len - 0.6)));
      osc('sine', hz(root - 12), t, len, g(bassBus, t, 0.13, 0.02, 0.6, Math.max(0, len - 0.6)));
    });
    // the leak: a low drone and a heartbeat under the search
    osc('sine', hz(38), T.leak + 1, T.rw - T.leak - 1.5, g(bassBus, T.leak + 1, 0.14, 0.8, 0.8, T.rw - T.leak - 3.2));
    for (let t = T.leak + 1.5; t < T.rw - 1; t += 1) [0, 0.26].forEach((d, k) => osc('sine', 90, t + d, 0.3, g(drums, t + d, k ? 0.16 : 0.28, 0.004, 0.25), 40, 0.2));

    // drums
    const kick = (t, v) => {
      osc('sine', 150, t, 0.4, g(drums, t, v, 0.002, 0.38), 42, 0.12);
      hiss(t, 0.01, g(filt('highpass', 3000, 0.7, drums), t, v * 0.3, 0.001, 0.008));
      pump.gain.setValueAtTime(1, t); pump.gain.linearRampToValueAtTime(0.6, t + 0.01); pump.gain.linearRampToValueAtTime(1, t + 0.22);
    };
    const clap = (t, v) => { const b = filt('bandpass', 1500, 0.9, drums); [0, 0.011, 0.022].forEach((d, i) => hiss(t + d, i === 2 ? 0.2 : 0.01, g(b, t + d, v, 0.001, i === 2 ? 0.18 : 0.01))); };
    const hat = (t, v) => hiss(t, 0.05, g(filt('highpass', 7500, 0.7, drums), t, v, 0.001, 0.04));
    const crash = (t, v) => hiss(t, 2, g(filt('highpass', 4200, 0.6, drums), t, v, 0.002, 1.8));
    for (let t = 1; t < T.outro - 0.01; t += 0.5) {
      const sec = section(t), beat = Math.round((t - 1) / 0.5) % 4;
      if (sec === 'day') { if (beat % 2 === 0) kick(t, 0.32); hat(t + 0.25, 0.06); }
      if (sec === 'cmp' && t >= 4) { kick(t, 0.36); hat(t + 0.25, 0.08); if (beat === 3) clap(t, 0.18); }
      if (sec === 'with' || sec === 'up') { kick(t, 0.52); hat(t + 0.25, 0.13); if (beat === 1 || beat === 3) clap(t, 0.32); }
      if (sec === 'up' && t >= T.admin + 4) { hat(t + 0.125, 0.06); hat(t + 0.375, 0.06); }
      if (sec === 'leak2' && t >= T.leak2 + 1.4 && beat % 2 === 0) kick(t, 0.4);
    }
    [4.0, at('front'), T.with, T.calm, T.uses, at('agents'), T.admin, T.outro].forEach((t) => crash(t, 0.2));
    // a riser into "with SecNote" after the tape stops, and into the resolved second leak
    [[T.with - 0.7, T.with], [T.calm - 1.6, T.calm]].forEach(([a, b]) => {
      const f = filt('bandpass', 400, 1.4, music); f.frequency.setValueAtTime(400, a); f.frequency.exponentialRampToValueAtTime(6000, b);
      const v = ctx.createGain(); v.gain.setValueAtTime(0, a); v.gain.linearRampToValueAtTime(0.28, b - 0.04); v.gain.linearRampToValueAtTime(0, b); v.connect(f);
      hiss(a, b - a, v);
    });
    // transitions: fast-forward whooshes and the tape rewind
    const SFXQ = [];
    SFXQ.push({ t: T.leak - 0.7, n: 'whoosh', dur: 1.4 }, { t: T.leak2 - 0.7, n: 'whoosh', dur: 1.4 }, { t: T.rw - 0.7, n: 'rewind', dur: 1.6 });

    // ----- sound effects from the scene cues -----
    const SFX = {
      key(t, c, r) {
        hiss(t, 0.04, g(filt('bandpass', 2600 + r() * 2200, 1.3, fx), t, 0.22 + r() * 0.12, 0.001, 0.03));
        osc('sine', 170 + r() * 40, t, 0.04, g(fx, t, 0.09, 0.001, 0.03));
      },
      paste(t, c, r) { SFX.key(t, c, r); SFX.key(t + 0.06, c, r); osc('sine', 1200, t + 0.05, 0.1, g(fx, t + 0.05, 0.07, 0.003, 0.08), 1700, 0.05); },
      enter(t) { hiss(t, 0.08, g(filt('bandpass', 1800, 0.8, fx), t, 0.45, 0.001, 0.06)); osc('sine', 120, t, 0.12, g(fx, t, 0.35, 0.002, 0.09), 70, 0.08); },
      send(t) {
        const b = filt('bandpass', 600, 1.2, fx); b.frequency.setValueAtTime(600, t); b.frequency.exponentialRampToValueAtTime(3800, t + 0.25);
        hiss(t, 0.35, g(b, t, 0.35, 0.08, 0.2)); osc('sine', 620, t, 0.2, g(fx, t, 0.08, 0.01, 0.15), 1250, 0.15);
      },
      pop(t, c) { const f = NOTE(c.note || 'C5'), v = 0.3 * (c.gain || 1); osc('sine', f * 0.7, t, 0.25, g(fx, t, v, 0.004, 0.2), f, 0.03); osc('triangle', f * 2, t, 0.12, g(fx, t, v * 0.25, 0.003, 0.08)); },
      whoosh(t, c) {
        const d = c.dur || 0.6, b = filt('bandpass', 300, 1.4, fx);
        b.frequency.setValueAtTime(300, t); b.frequency.exponentialRampToValueAtTime(2600, t + d * 0.55); b.frequency.exponentialRampToValueAtTime(500, t + d);
        const v = ctx.createGain(); v.gain.setValueAtTime(0, t); v.gain.linearRampToValueAtTime(0.5, t + d * 0.55); v.gain.linearRampToValueAtTime(0, t + d); v.connect(b);
        hiss(t, d, v);
      },
      detect(t, c) { bell(t, NOTE(c.note || 'E6'), 0.13, fx, 0.6); },
      warn(t) { [0, 0.13].forEach((d, i) => osc('triangle', i ? 740 : 880, t + d, 0.12, g(filt('lowpass', 2500, 0.7, fx), t + d, 0.22, 0.005, 0.1))); },
      block(t) {
        osc('sine', 150, t, 0.35, g(fx, t, 0.5, 0.003, 0.3), 55, 0.25);
        hiss(t, 0.12, g(filt('lowpass', 700, 0.7, fx), t, 0.35, 0.002, 0.1));
        bell(t + 0.02, 1320, 0.07, fx, 0.5);
      },
      check(t, c) { hiss(t, 0.02, g(filt('highpass', 2500, 0.7, fx), t, 0.25, 0.001, 0.012)); osc('sine', 2400 + 300 * (c.i || 0), t, 0.06, g(fx, t, 0.08, 0.002, 0.05)); },
      click(t) { hiss(t, 0.02, g(filt('highpass', 2000, 0.7, fx), t, 0.45, 0.001, 0.012)); osc('sine', 1800, t, 0.03, g(fx, t, 0.12, 0.001, 0.02)); },
      digital(t, c, r) {
        const out = filt('lowpass', 7000, 0.7, fx), n = Math.round((c.dur || 1) * 28);
        for (let k = 0; k < n; k++) { const tt = t + k / 28 + r() * 0.02; osc('square', 1800 + Math.floor(r() * 8) * 450, tt, 0.03, g(out, tt, 0.035, 0.001, 0.025)); }
      },
      lock(t) {
        [0, 0.05].forEach((d) => hiss(t + d, 0.06, g(filt('bandpass', 3200, 3, fx), t + d, 0.55, 0.001, 0.05)));
        bell(t + 0.05, 1650, 0.08, fx, 0.35);
        osc('sine', 95, t + 0.05, 0.2, g(fx, t + 0.05, 0.4, 0.002, 0.16), 60, 0.12);
      },
      chime(t, c) { const v = ctx.createGain(); v.gain.value = 1; v.connect(fx); send(v, 0.6); (c.notes || []).forEach((n, i) => bell(t + i * 0.11, NOTE(n), 0.16, v, 1.8)); },
      ping(t, c) { bell(t, NOTE(c.note || 'E6'), 0.12, fx, 0.9); },
      tick(t) { osc('sine', 2400, t, 0.03, g(fx, t, 0.15, 0.001, 0.015)); },
      burn(t, c, r) {
        const d = c.dur || 1, bed = filt('lowpass', 600, 0.7, fx);
        bed.frequency.setValueAtTime(900, t); bed.frequency.exponentialRampToValueAtTime(180, t + d);
        hiss(t, d, g(bed, t, 0.4, 0.06, d * 0.8));
        const cr = filt('bandpass', 2600, 0.8, fx);
        for (let k = 0; k < d * 70; k++) { const tt = t + r() * d; hiss(tt, 0.01, g(cr, tt, 0.1 + r() * 0.3, 0.001, 0.006)); }
        osc('sine', 520, t, d, g(fx, t, 0.06, 0.05, d * 0.8), 110, d);
      },
      gone(t) { const v = g(fx, t, 0.16, 0.01, 0.8); send(v, 0.5); osc('sine', 660, t, 0.8, v, 330, 0.5); osc('triangle', 990, t, 0.6, g(fx, t, 0.05, 0.01, 0.5), 495, 0.5); },
      chip(t, c) { const f = NOTE(c.note || 'C5'); osc('triangle', f, t, 0.3, g(fx, t, 0.16, 0.003, 0.25)); osc('sine', f * 2, t, 0.12, g(fx, t, 0.05, 0.002, 0.1)); },
      glitch(t, c, r) {
        const out = filt('bandpass', 1800, 0.8, fx);
        for (let k = 0; k < 9; k++) { const tt = t + k * 0.035 + r() * 0.015; osc('square', 120 + Math.floor(r() * 12) * 140, tt, 0.03, g(out, tt, 0.12, 0.001, 0.025)); hiss(tt, 0.02, g(out, tt, 0.18, 0.001, 0.015)); }
      },
      rewind(t, c) {
        const d = c.dur || 1.4, b = filt('bandpass', 3200, 1.2, fx);
        b.frequency.setValueAtTime(3200, t); b.frequency.exponentialRampToValueAtTime(260, t + d);
        const v = ctx.createGain(); v.gain.setValueAtTime(0, t); v.gain.linearRampToValueAtTime(0.5, t + 0.15); v.gain.setValueAtTime(0.5, t + d - 0.25); v.gain.linearRampToValueAtTime(0, t + d); v.connect(b);
        hiss(t, d, v);
        const tr = ctx.createGain(); tr.gain.value = 0.05; tr.connect(fx);
        const lfo = ctx.createOscillator(); lfo.frequency.setValueAtTime(9, t); lfo.frequency.linearRampToValueAtTime(22, t + d);
        const lg = ctx.createGain(); lg.gain.value = 0.04; lfo.connect(lg); lg.connect(tr.gain); lfo.start(t); lfo.stop(t + d);
        osc('sawtooth', 900, t, d, tr, 90, d);
      },
      impact(t) {
        osc('sine', 80, t, 2, g(fx, t, 0.85, 0.003, 1.8), 30, 0.9);
        hiss(t, 0.8, g(filt('lowpass', 900, 0.7, fx), t, 0.45, 0.002, 0.7));
        const v = g(filt('highpass', 4800, 0.6, fx), t, 0.2, 0.002, 2.2); send(v, 0.4); hiss(t, 2.2, v);
      },
    };
    SFXQ.concat(P.cues).forEach((c, i) => { if (SFX[c.n] && c.t < END) SFX[c.n](c.t, c, P.rng(1000 + i)); });
  }

  P.audio = {
    buffer: null,
    async render() {
      if (this.buffer) return this.buffer;
      const ctx = new OfflineAudioContext(2, Math.ceil(SR * P.total), SR);
      score(ctx);
      const b = await ctx.startRendering();
      // peak-normalise to -1 dBFS for the preview; the video gets loudness normalisation on top
      let peak = 0;
      for (let c = 0; c < 2; c++) for (const v of b.getChannelData(c)) peak = Math.max(peak, Math.abs(v));
      const k = peak > 0 ? 0.89 / peak : 1;
      for (let c = 0; c < 2; c++) { const d = b.getChannelData(c); for (let i = 0; i < d.length; i++) d[i] *= k; }
      return (this.buffer = b);
    },
    wavBase64() {
      const b = this.buffer, n = b.length, L = b.getChannelData(0), R = b.getChannelData(1);
      const dv = new DataView(new ArrayBuffer(44 + n * 4)), w = (o, s) => [...s].forEach((ch, i) => dv.setUint8(o + i, ch.charCodeAt(0)));
      w(0, 'RIFF'); dv.setUint32(4, 36 + n * 4, true); w(8, 'WAVEfmt '); dv.setUint32(16, 16, true); dv.setUint16(20, 1, true); dv.setUint16(22, 2, true);
      dv.setUint32(24, SR, true); dv.setUint32(28, SR * 4, true); dv.setUint16(32, 4, true); dv.setUint16(34, 16, true); w(36, 'data'); dv.setUint32(40, n * 4, true);
      for (let i = 0, o = 44; i < n; i++, o += 4) {
        dv.setInt16(o, Math.round(Math.max(-1, Math.min(1, L[i])) * 32767), true);
        dv.setInt16(o + 2, Math.round(Math.max(-1, Math.min(1, R[i])) * 32767), true);
      }
      const u8 = new Uint8Array(dv.buffer); let s = '';
      for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
      return btoa(s);
    },
    // live preview playback
    play(T) {
      this.stop();
      this.ctx = this.ctx || new AudioContext();
      const src = this.ctx.createBufferSource(); src.buffer = this.buffer; src.connect(this.ctx.destination);
      src.start(0, T); this.src = src; this.t0 = this.ctx.currentTime - T;
    },
    stop() { if (this.src) { try { this.src.stop(); } catch (e) { /* already stopped */ } this.src = null; } },
    time() { return this.ctx.currentTime - this.t0; },
  };
})();
