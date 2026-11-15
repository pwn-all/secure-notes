#!/usr/bin/env node
// Renders the film frame by frame in headless Chromium and muxes it with its own sound track.
//   node promo/render.mjs [--lang en] [--fps 30] [--crf 20] [--workers 4] [--from 0] [--to 119] [--out promo/out/secnote-promo-<lang>.mp4]
//   node promo/render.mjs --shots 3.2,17.5,40     # just PNG frames at those times → promo/out/shots/
//   node promo/render.mjs --wav                   # just the sound track (not normalised) → promo/out/secnote-promo-<lang>.wav
// Needs Playwright with its Chromium (resolvable as `playwright`, or PLAYWRIGHT=/path/to/node_modules/playwright) and ffmpeg on PATH.
import { createRequire } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = createRequire(import.meta.url)(process.env.PLAYWRIGHT || 'playwright');
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const lang = arg('lang', 'en'), fps = +arg('fps', 30), crf = String(arg('crf', 20)), workers = Math.max(1, +arg('workers', 4));
const shots = arg('shots');
const out = resolve(arg('out', join(here, 'out', `secnote-promo-${lang}.mp4`)));
const url = pathToFileURL(join(here, 'index.html')).href + `?render=1&lang=${encodeURIComponent(lang)}`;

const browser = await chromium.launch();
const open = async () => {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  page.on('pageerror', (e) => { console.error('page error:', e.message); process.exitCode = 1; });
  page.on('console', (m) => { if (m.type() === 'error') console.error('console:', m.text()); });
  await page.goto(url);
  await page.waitForFunction(() => window.__ready === true || window.__error, null, { timeout: 60000 });
  const err = await page.evaluate(() => window.__error);
  if (err) throw new Error(err);
  return page;
};

try {
  if (process.argv.includes('--wav')) {
    const page = await open(), wav = out.replace(/\.mp4$/, '') + '.wav';
    mkdirSync(dirname(wav), { recursive: true });
    writeFileSync(wav, Buffer.from(await page.evaluate(async () => { await P.audio.render(); return P.audio.wavBase64(); }), 'base64'));
    console.log(wav);
  } else if (shots) {
    const page = await open(), dir = join(here, 'out', 'shots');
    mkdirSync(dir, { recursive: true });
    for (const t of shots.split(',').map(Number)) {
      await page.evaluate((t) => P.seek(t), t);
      const file = join(dir, `${lang}-${t.toFixed(2)}.png`);
      writeFileSync(file, await page.screenshot({ type: 'png' }));
      console.log(file);
    }
  } else {
    const pages = await Promise.all(Array.from({ length: workers }, open));
    const total = await pages[0].evaluate(() => P.total);
    const from = +arg('from', 0), to = Math.min(+arg('to', total), total), n = Math.round((to - from) * fps);
    mkdirSync(dirname(out), { recursive: true });

    // sound: rendered in the page with the same code as the preview, loudness-normalised (two-pass loudnorm)
    const wav = out.replace(/\.mp4$/, '') + '.wav';
    writeFileSync(wav, Buffer.from(await pages[0].evaluate(async () => { await P.audio.render(); return P.audio.wavBase64(); }), 'base64'));
    const probe = spawnSync('ffmpeg', ['-hide_banner', '-nostats', '-ss', String(from), '-to', String(to), '-i', wav,
      '-af', 'loudnorm=I=-14:TP=-2:LRA=11:print_format=json', '-f', 'null', '-'], { encoding: 'utf8' });
    const m = JSON.parse(probe.stderr.match(/\{[^{}]*"input_i"[^{}]*\}/)[0]);
    const norm = `loudnorm=I=-14:TP=-2:LRA=11:measured_I=${m.input_i}:measured_TP=${m.input_tp}:measured_LRA=${m.input_lra}:measured_thresh=${m.input_thresh}:offset=${m.target_offset}:linear=true`;

    const ff = spawn('ffmpeg', ['-y', '-hide_banner', '-loglevel', 'error',
      '-f', 'image2pipe', '-framerate', String(fps), '-i', '-',
      '-ss', String(from), '-to', String(to), '-i', wav,
      '-map', '0:v', '-map', '1:a', '-t', String(n / fps),
      '-c:v', 'libx264', '-preset', 'slow', '-crf', crf, '-pix_fmt', 'yuv420p', '-profile:v', 'high',
      '-color_primaries', 'bt709', '-color_trc', 'bt709', '-colorspace', 'bt709',
      '-af', norm + ',alimiter=limit=0.75:attack=2:release=50:level=false', '-ar', '48000', '-c:a', 'aac', '-b:a', '192k', '-movflags', '+faststart', out], { stdio: ['pipe', 'inherit', 'inherit'] });
    const closed = new Promise((ok, no) => ff.on('close', (c) => (c ? no(new Error('ffmpeg exited with ' + c)) : ok())));

    // workers take every Nth frame; frames are written strictly in order
    const ready = new Map(); let next = 0; const t0 = Date.now();
    await Promise.all(pages.map(async (page, w) => {
      for (let i = w; i < n; i += workers) {
        await page.evaluate((t) => P.seek(t), from + i / fps);
        ready.set(i, await page.screenshot({ type: 'jpeg', quality: 95 }));
        while (ready.has(next)) {
          const buf = ready.get(next); ready.delete(next); next++;
          if (next % (fps * 5) === 0) console.log(`${(next / fps).toFixed(0)} s / ${(n / fps).toFixed(0)} s  (${((Date.now() - t0) / 1000).toFixed(0)} s)`);
          if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once('drain', r));
        }
      }
    }));
    ff.stdin.end();
    await closed;
    rmSync(wav);
    console.log(`${out}  (${n} frames, ${fps} fps, loudness ${m.input_i} → -14 LUFS)`);
  }
} finally {
  await browser.close();
}
