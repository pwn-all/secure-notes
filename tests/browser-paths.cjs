// Browser check that the frontend works wherever it is served: a domain root, a subdomain and a
// path such as /notes/. For each deployment a real Chromium loads the page, loads a language
// file, registers the service worker for the page's directory, sends a note through the
// same-origin API, opens the link, and reloads the page offline from the service worker cache.
// Every request the page makes must stay inside its directory (the API lives at the origin root).
//
// Needs openssl and Playwright with Chromium; point PLAYWRIGHT at the package if it is not
// installed here. Certificates and signing keys below are isolated test material.
//   PLAYWRIGHT=/path/to/node_modules/playwright node tests/browser-paths.cjs --binary target/release/secure_notes
const assert = require('node:assert/strict');
const https = require('node:https');
const net = require('node:net');
const { once } = require('node:events');
const { spawn, execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync, statSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { resolve, join, extname, normalize, sep } = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');

const DEPLOYMENTS = ['https://domain.test/', 'https://sub.domain.test/', 'https://domain.test/notes/', 'https://sub.domain.test/notes/'];
const API_PATHS = /^\/(api\/|info$|\.well-known\/api-catalog$)/;
const WEBSITE = resolve('website');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.md': 'text/markdown; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml' };

async function unusedPort() {
  const listener = net.createServer().listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const { port } = listener.address();
  await new Promise(done => listener.close(done));
  return port;
}

async function main() {
  const directory = mkdtempSync(join(tmpdir(), 'secnote-paths-'));
  const cert = join(directory, 'cert.pem'), key = join(directory, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1',
    '-subj', '/CN=domain.test', '-addext', 'subjectAltName=DNS:domain.test,DNS:sub.domain.test,DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  const binaryArg = process.argv.indexOf('--binary');
  const binary = resolve(binaryArg === -1 ? 'target/release/secure_notes' : process.argv[binaryArg + 1]);
  const apiPort = await unusedPort(), frontPort = await unusedPort();
  let logs = '', browser, front;
  const api = spawn(binary, [], { cwd: resolve('.'), stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env,
    HTTP_BIND_ADDR: '127.0.0.1:' + await unusedPort(), HTTPS_BIND_ADDR: '127.0.0.1:' + apiPort, PUBLIC_HOST: 'localhost',
    TLS_CERT_PATH: cert, TLS_KEY_PATH: key, SIGNING_KEY: require('./fixtures/signed-response.json').seed,
    RATE_INIT_PER_MIN: '500', RATE_CREATE_PER_MIN: '500', RATE_VIEW_PER_MIN: '500', RUST_LOG: 'secure_notes=info' } });
  api.stdout.on('data', chunk => { logs += chunk; });
  api.stderr.on('data', chunk => { logs += chunk; });

  try {
    // Reuse the real server's security headers, so the CSP is enforced for every deployment.
    let securityHeaders;
    for (let attempt = 0; !securityHeaders; attempt++) {
      try {
        securityHeaders = await new Promise((done, fail) => https.get({ host: '127.0.0.1', port: apiPort, path: '/', rejectUnauthorized: false },
          response => { response.resume(); done(response.headers); }).on('error', fail));
      } catch (error) {
        if (attempt > 50) throw new Error('API server did not start: ' + logs);
        await new Promise(done => setTimeout(done, 200));
      }
    }
    const copied = ['content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'x-frame-options'];
    assert.match(securityHeaders['content-security-policy'] || '', /script-src 'self'/);

    // The front server hosts the static website only under the deployment being tested and
    // passes API paths to the SecNote server; anything else is a stray request.
    const state = { host: '', base: '/', down: false, stray: [] };
    front = https.createServer({ cert: readFileSync(cert), key: readFileSync(key) }, (req, res) => {
      const host = (req.headers.host || '').replace(/:\d+$/, '');
      const path = decodeURIComponent(new URL(req.url, 'https://x').pathname);
      if (state.down) { req.socket.destroy(); return; }
      if (API_PATHS.test(path)) {
        const upstream = https.request({ host: '127.0.0.1', port: apiPort, path: req.url, method: req.method, rejectUnauthorized: false,
          headers: { ...req.headers, host: 'localhost' } }, response => { res.writeHead(response.statusCode, response.headers); response.pipe(res); });
        upstream.on('error', () => { res.writeHead(502); res.end(); });
        req.pipe(upstream);
        return;
      }
      if (host === state.host && path + '/' === state.base) { res.writeHead(301, { location: state.base }); res.end(); return; }
      let file = host === state.host && path.startsWith(state.base) ? normalize(join(WEBSITE, path.slice(state.base.length))) : null;
      if (file && (file + sep).startsWith(WEBSITE + sep) && path.endsWith('/')) file = join(file, 'index.html');
      let found = false;
      try { found = !!file && (file + sep).startsWith(WEBSITE + sep) && statSync(file).isFile(); } catch {}
      if (!found) {
        state.stray.push(host + path);
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
        return;
      }
      const headers = { 'content-type': TYPES[extname(file)] || 'application/octet-stream', 'cache-control': 'no-cache' };
      for (const name of copied) if (securityHeaders[name]) headers[name] = securityHeaders[name];
      res.writeHead(200, headers);
      res.end(readFileSync(file));
    });
    front.listen(frontPort, '127.0.0.1');
    await once(front, 'listening');

    browser = await chromium.launch({ args: ['--ignore-certificate-errors',
      '--host-resolver-rules=MAP domain.test 127.0.0.1, MAP sub.domain.test 127.0.0.1'] });

    for (const deployment of DEPLOYMENTS) {
      const deploymentUrl = new URL(deployment);
      const base = `https://${deploymentUrl.hostname}:${frontPort}${deploymentUrl.pathname}`;
      Object.assign(state, { host: deploymentUrl.hostname, base: deploymentUrl.pathname, down: false, stray: [] });
      const context = await browser.newContext({ locale: 'ru-RU', viewport: { width: 1280, height: 800 } });
      const errors = [];
      const page = await context.newPage();
      page.on('pageerror', error => errors.push(error.message));
      try {
        // A path without its trailing slash is redirected to the directory.
        if (base.endsWith('/notes/')) {
          await page.goto(base.slice(0, -1));
          assert.equal(page.url(), base);
        } else {
          await page.goto(base);
        }
        await page.waitForSelector('#apiDot.ok', { timeout: 20000 });
        assert.equal(await page.textContent('.hero-title'), 'Каким секретом хотите поделиться?', 'the language file loads from the page directory');
        const scope = await page.evaluate(async () => (await navigator.serviceWorker.ready).scope);
        assert.equal(scope, base, 'the service worker scope is the page directory');
        const manifest = await page.evaluate(async () => {
          const href = document.querySelector('link[rel=manifest]').href;
          const data = await (await fetch(href)).json();
          return { start: new URL(data.start_url, href).href, scope: new URL(data.scope, href).href };
        });
        assert.deepEqual(manifest, { start: base, scope: base }, 'the installed app opens this deployment');

        const secret = 'path check ' + deployment;
        await page.fill('#noteInput', secret);
        await page.click('#sendBtn');
        await page.waitForSelector('.msg-link .link-box', { timeout: 60000 });
        const link = (await page.textContent('.msg-link .link-text')).trim();
        assert.ok(link.startsWith(base + '?p='), `the link opens this page: ${link.replace(/#.*/, '#…')}`);

        const reader = await context.newPage();
        reader.on('pageerror', error => errors.push('reader: ' + error.message));
        await reader.goto(link);
        await reader.waitForFunction(() => document.querySelector('#revealBtn:not([disabled])') ||
          !document.querySelector('#oApiTrust').classList.contains('hidden'), null, { timeout: 30000 });
        if (await reader.isVisible('#apiTrustAccept')) await reader.click('#apiTrustAccept');
        await reader.waitForSelector('#revealBtn:not([disabled])', { timeout: 30000 });
        await reader.click('#revealBtn');
        await reader.waitForSelector('.note-actions', { timeout: 30000 });
        assert.match(await reader.textContent('#chatLog'), new RegExp(secret.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')));
        await reader.close();

        // Offline: the server drops every connection, the service worker serves the shell.
        await page.reload();
        await page.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 10000 });
        state.down = true;
        await page.reload();
        await page.waitForSelector('#composer', { timeout: 10000 });
        await page.waitForSelector('#apiDot.err', { timeout: 20000 });
        state.down = false;

        assert.deepEqual(state.stray, [], 'every request stays inside the page directory or goes to the API');
        assert.deepEqual(errors, [], 'no page errors');
        console.log(`PASS: ${deployment} loads, registers its service worker, sends and opens a note, works offline`);
      } finally {
        await context.close();
      }
    }
  } catch (error) {
    if (logs) console.error(logs.split('\n').slice(-20).join('\n'));
    throw error;
  } finally {
    await browser?.close();
    front?.close();
    api.kill();
    rmSync(directory, { recursive: true, force: true });
  }
}

main().catch(error => { console.error('FAIL:', error.message); process.exit(1); });
