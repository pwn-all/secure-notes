# SecNote promo film (119 s, English)

The source of the promo film. The video itself is not kept in git: `node promo/render.mjs` makes
`promo/out/secnote-promo-en.mp4` (1920×1080, 30 fps, H.264 + AAC 48 kHz, −14 LUFS).

The HTML here is the master. The film is a pure function of time (`P.seek(T)` sets every scene for second T), so the
browser preview, scrubbing and the frame-by-frame render show the same picture. Music and sound effects are synthesised
in the page from the scenes' own cues, so they stay in sync after any change.

## Story

| time | scene | what the viewer learns |
|---|---|---|
| 0:00–0:28 | compare | "Sending someone a password?", then SecNote next to typical open-source one-time secret apps, seven rows with a plain explanation each; row 1, the key difference: the app is not tied to a server |
| 0:28–0:40 | front | the page is plain HTML and JavaScript: a local copy (`file://`) switches between servers, only API calls go out, no page code comes from the server; offline, Tor Browser, pinned keys |
| 0:40–0:49 | share | "A real-life case": without SecNote, four employees paste passwords into a team chat, a messenger, an e-mail and a helpdesk ticket |
| 0:49–0:59 | leak | ▶▶ 6 months later the history leaks; a search for "password" finds all four: Exposed 4 / 4 |
| 0:59–1:11 | rewind | ◀◀ back to the same day with SecNote (the real chat UI): the apps get one-time links, each is read once and destroyed |
| 1:11–1:19 | leak2 | ▶▶ the same leak finds only dead links, "This note is already gone": Exposed 0 / 4 |
| 1:19–1:33 | uses | onboarding, partners and contractors (no account), files (when the operator enables them), in person by QR code |
| 1:33–1:43 | agents | an AI agent hands over a one-time link through the WebMCP tool `create_encrypted_note` (operator opt-in); the discovery files `llms.txt`, `.well-known/agent-skills/index.json`, the API catalog and `index.md` |
| 1:43–1:53 | admin | one admin runs SecNote on the company domain; it serves every app because it is just a link |
| 1:53–1:59 | outro | lock, monospaced name, squiggle, "Share it once. Leave nothing to leak.", badges, repository address |

A timeline at the bottom (Without / With SecNote, Mar 3 → Sep 14) carries the case. The look follows `website/og.svg`:
dot grid, `#111122`, slate blue, monospaced type. The four apps are generic, without brands.

Everything shown is fictional: the company Acme (`notes.acme.corp`, `admin@acme.corp`, `it@acme.corp`), the people,
passwords, note IDs, keys and pins. Other hosts are reserved or non-existent names (`notes.instance`, `notes.example`).
The comparison names no products; its values come from the comparison table in the main README.

## Preview

Open `promo/index.html` in Chrome (file:// is fine). Space plays/pauses, ←/→ steps one frame, Shift+←/→ one second.
`index.html?t=24.5` opens at a time, `?lang=de` uses `i18n/de.js`. Sound starts after "♪ sound ready".

## Render

Needs Playwright with its Chromium (resolvable as `playwright`, or `PLAYWRIGHT=/path/to/node_modules/playwright`) and
`ffmpeg` on PATH.

```
node promo/render.mjs --workers 6          # → promo/out/secnote-promo-en.mp4, about a minute on 8 cores
node promo/render.mjs --shots 13,26.5      # PNG frames → promo/out/shots/
node promo/render.mjs --lang de --fps 60   # another language, 60 fps
```

Options: `--crf` (quality, default 20), `--workers` (parallel browser pages, default 4), `--from`/`--to`, `--out`.

## Translate

Copy `i18n/en.js` to `i18n/<code>.js`, rename `PROMO_I18N.en` to `PROMO_I18N.<code>` and translate the values; keys you
leave out stay English. Take the `ui` strings from `website/langs/<code>.json` so the screens match the real app. The
bundled fonts (Manrope, Roboto Mono, SIL Open Font License 1.1) cover Latin, Latin Extended and Cyrillic.

## Files

| file | contents |
|---|---|
| `index.html` | stage, player controls, language loading (uses `../website/qrcode.min.js`) |
| `engine.js` | time math, easing, typing, pointer, dot-grid background, cuts (fast-forward, rewind, fade), timeline overlay hook |
| `scenes.js` | the ten scenes and the timeline overlay |
| `audio.js` | music (120 BPM) and effects, rendered with `OfflineAudioContext` |
| `style.css` | all styling; the SecNote screens copy the light theme of `website/styles.css` |
| `i18n/en.js` | every word of the film |
| `render.mjs` | headless Chromium → ffmpeg, loudness normalisation and a peak limiter |
