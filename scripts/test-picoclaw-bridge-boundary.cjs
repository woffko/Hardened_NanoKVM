#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const option = process.argv.indexOf('--script');
const script = path.resolve(option < 0
  ? 'kvmapp/picoclaw/skills/kvm-control/scripts/nanokvm-bridge.sh'
  : process.argv[option + 1]);
const token = 'synthetic-bridge-boundary-fixture';
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nanokvm-bridge-boundary-'));
const bin = path.join(root, 'bin');
const credential = path.join(root, 'token');
const record = path.join(root, 'requests.jsonl');
fs.mkdirSync(bin);
fs.writeFileSync(credential, `${token}\n`, { mode: 0o600 });
fs.writeFileSync(path.join(bin, 'curl'), `#!${process.execPath}
'use strict';
const fs = require('node:fs');
const args = process.argv.slice(2);
const fields = [];
const headerFiles = [];
let output, dump, body = '', writeStatus = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '-H' || args[i] === '--header') {
    const value = args[++i];
    if (value.startsWith('@')) {
      const file = value.slice(1);
      headerFiles.push({ file, mode: fs.statSync(file).mode & 0o777 });
      fields.push(...fs.readFileSync(file, 'utf8').trimEnd().split(/\\r?\\n/));
    } else fields.push(value);
  } else if (args[i] === '-o') output = args[++i];
  else if (args[i] === '-D') dump = args[++i];
  else if (args[i] === '--data') body = args[++i];
  else if (args[i] === '-w') { i++; writeStatus = true; }
}
const url = args.at(-1);
const status = process.env.BRIDGE_TEST_STATUS || '200';
fs.appendFileSync(process.env.BRIDGE_TEST_RECORD,
  JSON.stringify({ args, fields, headerFiles, url, body,
    inheritedToken: Boolean(process.env.NANOKVM_BRIDGE_INTERNAL_TOKEN || process.env.NANOKVM_INTERNAL_TOKEN),
  }) + '\\n');
if (process.env.BRIDGE_TEST_EXIT) process.exit(Number(process.env.BRIDGE_TEST_EXIT));
if (dump) fs.writeFileSync(dump, 'HTTP/1.1 ' + status + ' Fixture\\r\\n\\r\\n');
if (output) fs.writeFileSync(output, url.includes('/runtime/session')
  ? '{"code":0,"data":{"current_session":"fixture-session"}}'
  : '{"code":0,"data":{"accepted":true}}');
if (writeStatus) process.stdout.write(status);
`, { mode: 0o700 });

let passed = 0;
let failed = 0;
async function test(name, work) {
  try { await work(); passed++; process.stdout.write(`PASS ${name}\n`); }
  catch (error) {
    failed++;
    process.stderr.write(`FAIL ${name}: ${error.message}\n`);
  }
}

function environment(base, overrides = {}, real = false) {
  return {
    PATH: real ? '/usr/bin:/bin' : `${bin}:/usr/bin:/bin`,
    HOME: root, LC_ALL: 'C',
    NANOKVM_BRIDGE_BASE_URL: base,
    NANOKVM_BRIDGE_INTERNAL_TOKEN_FILE: credential,
    BRIDGE_TEST_RECORD: record,
    ...overrides,
  };
}

function invoke(base, { args = ['move', '--x', '1', '--y', '2'], discovery = false,
  overrides = {} } = {}) {
  fs.writeFileSync(record, '');
  const result = spawnSync('/bin/sh', [script,
    ...(discovery ? [] : ['--session-id', 'fixture-session']), ...args], {
    env: environment(base, overrides), encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  const requests = fs.readFileSync(record, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  return { ...result, requests };
}

function safeRequest(request, local) {
  assert.equal(request.args[0], '--disable', 'curlrc must be disabled first');
  assert(!request.args.some(arg => ['-L', '--location', '--location-trusted', '--follow'].includes(arg)),
    'control credentials must not follow redirects');
  assert(!request.args.some(arg => arg.includes(token)), 'credential must not enter curl argv');
  assert(!request.args.some(arg => arg.includes('fixture-session')), 'session must not enter curl argv');
  assert.equal(request.inheritedToken, false, 'legacy token override must not enter child environment');
  assert.equal(request.fields.includes(`X-NanoKVM-Internal-Token: ${token}`), local);
  assert(request.headerFiles.length > 0, 'headers need a private file');
  for (const header of request.headerFiles) {
    assert.equal(header.mode, 0o600);
    assert(!fs.existsSync(header.file), 'header file must be removed after the request');
  }
  assert.equal(request.args.includes('-k'), local);
  if (local) {
    const index = request.args.indexOf('--noproxy');
    assert(index >= 0 && request.args[index + 1] === '*', 'loopback must bypass proxies');
  }
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
}

function close(server) {
  server.closeAllConnections?.();
  return new Promise(resolve => server.close(resolve));
}

async function realRedirect() {
  let leaked = 0;
  const sink = http.createServer((req, res) => {
    if (req.headers['x-nanokvm-internal-token'] === token) leaked++;
    res.end('{"code":0}');
  });
  const origin = http.createServer((_req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.1:${sink.address().port}/unexpected-service` });
    res.end('synthetic redirect');
  });
  try {
    await listen(sink); await listen(origin);
    const result = await new Promise((resolve, reject) => {
      const child = spawn('/bin/sh', [script, '--session-id', 'fixture-session',
        'move', '--x', '1', '--y', '2'], {
        env: environment(`http://127.0.0.1:${origin.address().port}`, {}, true),
        stdio: ['ignore', 'ignore', 'ignore'],
      });
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('owned fixture timed out')); }, 5000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('close', code => { clearTimeout(timer); resolve(code); });
    });
    assert.equal(leaked, 0, 'redirect destination received internal credential');
    assert.notEqual(result, 0, 'redirect must not be reported as API success');
  } finally {
    await close(origin); await close(sink);
  }
}

function realInvoke(base, overrides = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('/bin/sh', [script, '--session-id', 'fixture-session',
      'move', '--x', '1', '--y', '2'], {
      env: environment(base, overrides, true), stdio: ['ignore', 'ignore', 'ignore'],
    });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('owned fixture timed out')); }, 5000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); resolve(code); });
  });
}

async function realProxyAndCurlrc(host) {
  let proxyRequests = 0;
  let localRequests = 0;
  let extraHeader = false;
  const proxy = http.createServer((_req, res) => { proxyRequests++; res.end('{"code":0}'); });
  const origin = http.createServer((req, res) => {
    if (req.headers['x-nanokvm-internal-token'] === token) localRequests++;
    extraHeader ||= req.headers['x-fixture-curlrc'] !== undefined;
    res.end('{"code":0}');
  });
  const curlrc = path.join(root, '.curlrc');
  try {
    await listen(proxy); await listen(origin);
    const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
    fs.writeFileSync(curlrc, `proxy = "${proxyUrl}"\nheader = "X-Fixture-Curlrc: must-not-be-used"\nlocation\n`, { mode: 0o600 });
    const result = await realInvoke(`http://${host}:${origin.address().port}`, {
      http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl, ALL_PROXY: proxyUrl,
      no_proxy: '', NO_PROXY: '',
    });
    assert.equal(result, 0, 'validated loopback must remain usable');
    assert.equal(proxyRequests, 0, 'loopback credential must bypass every configured proxy');
    assert.equal(localRequests, 1, 'local API must receive the internal credential');
    assert.equal(extraHeader, false, 'curlrc must not inject headers/options');
  } finally {
    fs.rmSync(curlrc, { force: true });
    await close(origin); await close(proxy);
  }
}

(async () => {
  try {
    for (const base of ['http://127.0.0.1', 'https://127.0.0.1:8443', 'http://localhost',
      'HTTP://LOCALHOST:8080', 'http://[::1]', 'https://[::1]:8443']) {
      await test(`local ${base}`, () => {
        const result = invoke(base);
        assert.equal(result.status, 0);
        assert.equal(result.requests.length, 1);
        safeRequest(result.requests[0], true);
        if (new URL(result.requests[0].url).hostname === 'localhost') {
          assert(result.requests[0].args.includes('--resolve'), 'localhost must be pinned');
        }
      });
    }
    for (const base of ['https://example.invalid', 'http://127.0.0.1.evil.invalid',
      'https://localhost.evil.invalid', 'https://[2001:db8::1]:8443']) {
      await test(`remote ${base}`, () => {
        const result = invoke(base);
        assert.equal(result.status, 0);
        assert.equal(result.requests.length, 1);
        safeRequest(result.requests[0], false);
      });
    }
    for (const base of ['http://127.0.0.1:80@evil.invalid', 'https://localhost:443@evil.invalid',
      'http://[::1]:80@evil.invalid', 'http://user@localhost', 'http://127.0.0.1%40evil.invalid',
      'ftp://127.0.0.1', 'file:///tmp/fixture', 'http://::1', 'http://localhost:',
      'http://localhost:-1', 'http://localhost:65536', 'http://localhost:80@evil.invalid/path',
      'http://localhost?query', 'http://localhost#fragment', 'http://localhost\\@evil.invalid',
      'http://localhost/line\nbreak']) {
      await test(`reject base ${JSON.stringify(base)}`, () => {
        const result = invoke(base);
        assert.notEqual(result.status, 0);
        assert.equal(result.requests.length, 0, 'bad base must fail before curl');
      });
    }
    for (const prefix of ['@evil.invalid/api', '//evil.invalid/api', '/api?query', '/api#fragment']) {
      await test(`reject API prefix ${prefix}`, () => {
        const result = invoke('http://127.0.0.1', { overrides: { NANOKVM_BRIDGE_API_PREFIX: prefix } });
        assert.notEqual(result.status, 0);
        assert.equal(result.requests.length, 0);
      });
    }
    for (const value of ['', ' \r\n', 'synthetic\nfixture', 'synthetic\rfixture',
      'synthetic\0fixture', Buffer.from([0xff]), 'x'.repeat(257), 'x'.repeat(1025)]) {
      await test('invalid local credential fails before curl', () => {
        const invalid = path.join(root, 'invalid-token');
        fs.writeFileSync(invalid, value, { mode: 0o600 });
        const result = invoke('http://127.0.0.1', { overrides: { NANOKVM_BRIDGE_INTERNAL_TOKEN_FILE: invalid } });
        assert.notEqual(result.status, 0);
        assert.equal(result.requests.length, 0);
      });
    }
    for (const value of [`${token}\r\n`, `  ${token} \t\n`]) {
      await test('outer whitespace preserves a valid legacy token', () => {
        const legacy = path.join(root, 'legacy-token');
        fs.writeFileSync(legacy, value, { mode: 0o600 });
        const result = invoke('http://127.0.0.1', { overrides: { NANOKVM_BRIDGE_INTERNAL_TOKEN_FILE: legacy } });
        assert.equal(result.status, 0);
        safeRequest(result.requests[0], true);
      });
    }
    for (const name of ['NANOKVM_BRIDGE_INTERNAL_TOKEN', 'NANOKVM_INTERNAL_TOKEN']) {
      await test('legacy override is consumed without child-environment exposure', () => {
        const result = invoke('http://127.0.0.1', { overrides: { [name]: token } });
        assert.equal(result.status, 0);
        safeRequest(result.requests[0], true);
      });
    }
    for (const session of ['fixture\r\ninjected: true', 'fixture session', 'x'.repeat(257)]) {
      await test('invalid session header fails before curl', () => {
        const result = invoke('http://127.0.0.1', { args: ['move', '--x', '1', '--y', '2', '--session-id', session] });
        assert.notEqual(result.status, 0);
        assert.equal(result.requests.length, 0);
      });
    }
    await test('curl failure still removes the private credential header file', () => {
      const result = invoke('http://127.0.0.1', { overrides: { BRIDGE_TEST_EXIT: '7' } });
      assert.notEqual(result.status, 0);
      assert.equal(result.requests.length, 1);
      safeRequest(result.requests[0], true);
    });
    await test('remote endpoint does not try to read a local credential', () => {
      const missing = path.join(root, 'missing-token');
      const result = invoke('https://example.invalid', { overrides: { NANOKVM_BRIDGE_INTERNAL_TOKEN_FILE: missing } });
      assert.equal(result.status, 0);
      safeRequest(result.requests[0], false);
    });
    await test('runtime session discovery preserves both protected requests', () => {
      const result = invoke('http://127.0.0.1', { discovery: true });
      assert.equal(result.status, 0);
      assert.equal(result.requests.length, 2);
      result.requests.forEach(request => safeRequest(request, true));
    });
    await test('binary screenshot uses the same control boundary', () => {
      const result = invoke('http://127.0.0.1', { args: ['screenshot', '--format', 'jpeg'] });
      assert.equal(result.status, 0);
      safeRequest(result.requests[0], true);
    });
    await test('target URL and Enter remain unrestricted HID payloads', () => {
      const target = 'http://127.0.0.1:80@target.invalid/arbitrary';
      const result = invoke('http://127.0.0.1', {
        args: ['open-url', '--url', target, '--focus-shortcut', 'CTRL,L'],
      });
      assert.equal(result.status, 0);
      const body = JSON.parse(result.requests[0].body);
      assert(body.actions.some(action => action.action === 'type' && action.text === target));
      assert(body.actions.some(action => action.action === 'hotkey' && action.keys.includes('ENTER')));
      safeRequest(result.requests[0], true);
    });
    await test('option values are payload, never session hints or global options', () => {
      const text = 'session:evil --base-url http://10.0.0.1 pico:other';
      const result = invoke('http://127.0.0.1', { args: ['type', '--text', text] });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.requests[0].body).text, text);
      assert(result.requests[0].fields.includes('X-PicoClaw-Session-ID: fixture-session'),
        'the typed text must not replace the session');
      safeRequest(result.requests[0], true);
      const bare = invoke('http://127.0.0.1', { args: ['type', '--text', '--base-url'] });
      assert.equal(bare.status, 0, bare.stderr);
      assert.equal(JSON.parse(bare.requests[0].body).text, '--base-url');
      assert(bare.requests[0].url.startsWith('http://127.0.0.1'), 'the typed text must not move the base URL');
    });
    await test('real localhost redirect never receives the internal credential', realRedirect);
    for (const host of ['127.0.0.1', 'localhost']) {
      await test(`real ${host} bypasses proxies and ignores curlrc`, () => realProxyAndCurlrc(host));
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  process.stdout.write(`bridge boundary: ${passed} passed, ${failed} failed\n`);
  if (failed) process.exitCode = 1;
})().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
