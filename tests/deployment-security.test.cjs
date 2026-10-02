const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, readdirSync, rmSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { tmpdir } = require('node:os');
const { spawnSync } = require('node:child_process');

// Exercise the real shell branches without needing root or Linux capabilities.
// Absolute runtime/ACME paths are relocated into a private temporary directory;
// only ownership, UID, capability execution, certbot and PID 1 are stubbed.
function harness() {
  const directory = mkdtempSync(join(tmpdir(), 'secnote-entrypoint-'));
  const runtime = join(directory, 'run/secnote');
  const sources = join(directory, 'letsencrypt/live/example.test');
  const bin = join(directory, 'bin');
  mkdirSync(sources, { recursive: true });
  mkdirSync(bin);
  writeFileSync(join(sources, 'fullchain.pem'), 'test certificate');
  writeFileSync(join(sources, 'privkey.pem'), 'test private key');
  const log = join(directory, 'commands.log');
  writeFileSync(log, '');
  const script = join(directory, 'entrypoint.sh');
  writeFileSync(script, readFileSync(resolve('scripts/docker-entrypoint.sh'), 'utf8')
    .replaceAll('/run/secnote', runtime)
    .replaceAll('/etc/letsencrypt', join(directory, 'letsencrypt')));
  const bashEnv = join(directory, 'mock-env.sh');
  writeFileSync(bashEnv, `
id() { if [[ "$*" == -u ]]; then printf '%s\\n' "\${FAKE_UID:-0}"; else command id "$@"; fi; }
cat() { if [[ "$1" == /proc/1/comm ]]; then printf '%s\\n' "\${FAKE_PID1_COMM:-secure_notes}"; else command cat "$@"; fi; }
kill() { printf 'kill:%s\\n' "$*" >> "$HARNESS_LOG"; }
install() {
  printf 'install:%s\\n' "$*" >> "$HARNESS_LOG"
  if [[ "\${FAKE_KEY_COPY_FAILURE:-0}" == 1 && "$*" == *privkey.pem* ]]; then return 73; fi
  local args=()
  while (( $# )); do
    case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac
  done
  command install "\${args[@]}"
}
`);
  writeFileSync(join(bin, 'setpriv'), `#!/usr/bin/env bash
set -euo pipefail
printf 'setpriv:%s\\n' "$*" >> "$HARNESS_LOG"
[[ "\${FAKE_SETPRIV_FAILURE:-0}" != 1 ]] || exit 77
while [[ "$1" == --* ]]; do shift; done
exec "$@"
`, { mode: 0o755 });
  writeFileSync(join(bin, 'certbot'), `#!/usr/bin/env bash
printf 'certbot:%s\\n' "$*" >> "$HARNESS_LOG"
`, { mode: 0o755 });
  writeFileSync(join(directory, 'secure_notes'), `#!/usr/bin/env bash
printf 'server:%s|%s|%s\\n' "$TLS_CERT_PATH" "$TLS_KEY_PATH" "\${PUBLIC_HOST:-}" >> "$HARNESS_LOG"
`, { mode: 0o755 });
  const baseEnv = { ...process.env, BASH_ENV: bashEnv, HARNESS_LOG: log,
    PATH: bin + ':' + process.env.PATH, FAKE_UID: '0',
    TLS_CERT_PATH: join(sources, 'fullchain.pem'), TLS_KEY_PATH: join(sources, 'privkey.pem') };
  for (const key of ['DOMAIN', 'EMAIL', 'HTTP_BIND_ADDR', 'HTTPS_BIND_ADDR', 'BIND_ADDR', 'LETSENCRYPT_STAGING', 'PUBLIC_HOST']) delete baseEnv[key];
  return {
    directory, runtime, sources,
    run(env = {}, args = []) { return spawnSync('bash', [script, ...args], { cwd: directory, env: { ...baseEnv, ...env }, encoding: 'utf8' }); },
    log() { return readFileSync(log, 'utf8'); },
    dispose() { rmSync(directory, { recursive: true, force: true }); },
  };
}

test('root entrypoint keeps only low-port capability and exposes private TLS copies to dedicated UID', () => {
  const h = harness();
  try {
    const result = h.run();
    assert.equal(result.status, 0, result.stderr);
    const log = h.log();
    assert.match(log, /setpriv:--reuid=65532 --regid=65532 --clear-groups/);
    for (const option of ['bounding-set', 'inh-caps', 'ambient-caps']) assert.ok(log.includes('--' + option + '=-all,+net_bind_service'));
    assert.ok(log.includes('--no-new-privs ./secure_notes'));
    assert.ok(log.includes('server:' + join(h.runtime, 'fullchain.pem') + '|' + join(h.runtime, 'privkey.pem')));
    assert.ok(log.includes('install:-d -o 0 -g 65532 -m 0750'));
    assert.ok(log.includes('install:-o 0 -g 65532 -m 0640'));
    assert.equal(statSync(h.runtime).mode & 0o777, 0o750);
    assert.equal(statSync(join(h.runtime, 'privkey.pem')).mode & 0o777, 0o640);
    assert.equal(readFileSync(join(h.runtime, 'privkey.pem'), 'utf8'), 'test private key');
    assert.deepEqual(readdirSync(h.runtime).sort(), ['fullchain.pem', 'privkey.pem']);
  } finally { h.dispose(); }
});

test('high-port entrypoint drops all capability sets and honors the legacy HTTPS bind alias', () => {
  const h = harness();
  try {
    const result = h.run({ HTTP_BIND_ADDR: '0.0.0.0:8080', BIND_ADDR: '[::]:8443' });
    assert.equal(result.status, 0, result.stderr);
    const log = h.log();
    for (const option of ['bounding-set', 'inh-caps', 'ambient-caps']) assert.ok(log.includes('--' + option + '=-all '));
    assert.ok(!log.includes('+net_bind_service'));
  } finally { h.dispose(); }
});

test('explicit nonroot certificates execute without certificate copying or privilege changes', () => {
  const h = harness();
  try {
    const result = h.run({ FAKE_UID: '12345' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(h.log(), /server:/);
    assert.ok(!h.log().includes('setpriv:'));
    assert.ok(!h.log().includes('install:'));
    assert.ok(!h.log().includes('certbot:'));
    const rejected = h.run({ FAKE_UID: '12345', TLS_CERT_PATH: '', TLS_KEY_PATH: '', DOMAIN: 'example.test', EMAIL: 'admin@example.test' });
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /automatic certificate setup requires root/);
  } finally { h.dispose(); }
});

test('automatic TLS setup passes staging safely and drops privileges before executing server', () => {
  const h = harness();
  try {
    const result = h.run({ TLS_CERT_PATH: '', TLS_KEY_PATH: '', DOMAIN: 'example.test', EMAIL: 'admin@example.test', LETSENCRYPT_STAGING: '1' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(h.log(), /certbot:certonly .* --email admin@example.test -d example.test --staging/);
    assert.match(h.log(), /setpriv:/);
    assert.ok(h.log().includes('|example.test'));
  } finally { h.dispose(); }
});

test('TLS refresh replaces both runtime copies before signaling the existing PID 1', () => {
  const h = harness();
  try {
    assert.equal(h.run().status, 0);
    writeFileSync(join(h.sources, 'fullchain.pem'), 'renewed certificate');
    writeFileSync(join(h.sources, 'privkey.pem'), 'renewed private key');
    const result = h.run({}, ['--reload-tls']);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(join(h.runtime, 'fullchain.pem'), 'utf8'), 'renewed certificate');
    assert.equal(readFileSync(join(h.runtime, 'privkey.pem'), 'utf8'), 'renewed private key');
    assert.match(h.log(), /kill:-HUP 1/);
    assert.equal(h.log().split('server:').length - 1, 1);
    assert.equal(h.log().split('setpriv:').length - 1, 1);
    const rejected = h.run({ FAKE_PID1_COMM: 'init' }, ['--reload-tls']);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /PID 1 is not the SecNote server/);
  } finally { h.dispose(); }
});

test('TLS copy failure leaves prior copies and running server untouched', () => {
  const h = harness();
  try {
    assert.equal(h.run().status, 0);
    writeFileSync(join(h.sources, 'fullchain.pem'), 'renewed certificate');
    const result = h.run({ FAKE_KEY_COPY_FAILURE: '1' }, ['--reload-tls']);
    assert.equal(result.status, 73);
    assert.equal(readFileSync(join(h.runtime, 'fullchain.pem'), 'utf8'), 'test certificate');
    assert.equal(readFileSync(join(h.runtime, 'privkey.pem'), 'utf8'), 'test private key');
    assert.deepEqual(readdirSync(h.runtime).sort(), ['fullchain.pem', 'privkey.pem']);
    assert.ok(!h.log().includes('kill:'));
  } finally { h.dispose(); }
});

test('privilege drop failure never falls back to running the server as root', () => {
  const h = harness();
  try {
    const result = h.run({ FAKE_SETPRIV_FAILURE: '1' });
    assert.equal(result.status, 77);
    assert.ok(!h.log().includes('server:'));
    const missing = h.run({ TLS_KEY_PATH: '' });
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /both TLS_CERT_PATH and TLS_KEY_PATH/);
  } finally { h.dispose(); }
});
