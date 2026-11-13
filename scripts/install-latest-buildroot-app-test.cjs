#!/usr/bin/env node

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const CryptoJS = require('../web/node_modules/crypto-js');
const { request } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const BASE_URL = `https://${TARGET_IP}`;
const SYSTEM_VERSION = process.env.EXPECTED_SOURCE_SYSTEM_VERSION || '';
const SOURCE_APP_VERSION = process.env.EXPECTED_SOURCE_APP_VERSION || '';
const APP_VERSION = process.env.EXPECTED_APP_VERSION || '';
const ARCHIVE_SHA256 = process.env.EXPECTED_APP_ARCHIVE_SHA256 || '';
const BACKEND_SHA256 = process.env.EXPECTED_BACKEND_SHA256 || '';
const LIBKVM_SHA256 = process.env.EXPECTED_LIBKVM_SHA256 || '';
const LIBKVM_MMF_SHA256 = process.env.EXPECTED_LIBKVM_MMF_SHA256 || '';
const REMOTE_SYSLOG = process.env.EXPECTED_REMOTE_SYSLOG || '';
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const APP_ARCHIVE = path.join(ROOT, 'build/artifacts/nanokvm-kvmapp-rust.tar.gz');
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `app-${APP_VERSION}-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');
const knownHostsPath = path.join(resultDir, 'known_hosts');

function step(message) {
  fs.appendFileSync(reportPath, `${new Date().toISOString()} ${message}\n`, { mode: 0o600 });
}

function fail(message) {
  throw new Error(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readSecret() {
  let input = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) input += chunk;
  return input.replace(/\r?\n$/, '');
}

async function hashFile(filename) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}

async function run(command, args, input = undefined, secret = undefined) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: ROOT,
      env: { HOME: '/home/w0w', USER: 'w0w', LANG: 'C', PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' },
      stdio: secret === undefined ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        const error = new Error(`${path.basename(command)} failed with exit code ${code}`);
        error.stderrBytes = Buffer.concat(stderr).length;
        reject(error);
      } else resolve(Buffer.concat(stdout));
    });
    if (secret !== undefined) child.stdio[3].end(secret);
    if (input !== undefined && child.stdin) child.stdin.end(input);
    else if (child.stdin) child.stdin.end();
  });
}

function encryptPassword(password) {
  return encodeURIComponent(CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString());
}

async function newContext() {
  return request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 60000 });
}

async function login(context, password) {
  const response = await context.post('/api/auth/login', {
    data: { username: 'admin', password: encryptPassword(password) },
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) fail('API login failed');
  return json.data.csrfToken;
}

async function api(context, csrfToken, pathname, method = 'GET', body = undefined) {
  const response = await context.fetch(pathname, {
    method,
    data: body,
    headers: method === 'GET' ? {} : { 'x-csrf-token': csrfToken },
    timeout: 15 * 60 * 1000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
  return json.data;
}

async function waitCycle(oldContext, label) {
  let offline = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await oldContext.get('/api/health', { timeout: 3000 });
      if (!response.ok()) offline = true;
    } catch {
      offline = true;
    }
    if (offline) break;
    await sleep(1000);
  }
  await oldContext.dispose();
  for (let attempt = 0; attempt < 180; attempt += 1) {
    const context = await newContext();
    try {
      const response = await context.get('/api/health', { timeout: 4000 });
      const json = await response.json();
      if (response.ok() && json?.code === 0 && json?.data?.status === 'ok') {
        step(`${label}_returned=yes`);
        return context;
      }
    } catch {}
    await context.dispose();
    await sleep(3000);
  }
  fail(`${label} did not return`);
}

async function ssh(password, command) {
  return (await run(
    SSHPASS,
    [
      '-d', '3', 'ssh', '-o', 'ConnectTimeout=10', '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsPath}`,
      `root@${TARGET_IP}`, command,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  )).toString('utf8');
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing app test install without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  for (const [name, value] of Object.entries({
    EXPECTED_SOURCE_SYSTEM_VERSION: SYSTEM_VERSION,
    EXPECTED_SOURCE_APP_VERSION: SOURCE_APP_VERSION,
    EXPECTED_APP_VERSION: APP_VERSION,
    EXPECTED_APP_ARCHIVE_SHA256: ARCHIVE_SHA256,
    EXPECTED_BACKEND_SHA256: BACKEND_SHA256,
    EXPECTED_LIBKVM_SHA256: LIBKVM_SHA256,
    EXPECTED_LIBKVM_MMF_SHA256: LIBKVM_MMF_SHA256,
    EXPECTED_REMOTE_SYSLOG: REMOTE_SYSLOG,
    APP_METADATA: process.env.APP_METADATA,
    APP_SIGNATURE: process.env.APP_SIGNATURE,
  })) {
    if (!value) fail(`${name} is required`);
  }
  for (const [name, value] of Object.entries({
    EXPECTED_APP_ARCHIVE_SHA256: ARCHIVE_SHA256,
    EXPECTED_BACKEND_SHA256: BACKEND_SHA256,
    EXPECTED_LIBKVM_SHA256: LIBKVM_SHA256,
    EXPECTED_LIBKVM_MMF_SHA256: LIBKVM_MMF_SHA256,
  })) {
    if (!/^[a-f0-9]{64}$/.test(value)) fail(`${name} must be a lowercase SHA-256`);
  }
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  if ((await hashFile(APP_ARCHIVE)) !== ARCHIVE_SHA256) fail('app archive hash mismatch');

  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    fail('unexpected SSH fingerprint');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });

  let context = await newContext();
  let csrfToken = await login(context, password);
  const beforeSystem = (await api(context, csrfToken, '/api/system-update/version')).current?.version;
  const beforeApp = (await api(context, csrfToken, '/api/application/version')).current;
  if (beforeSystem !== SYSTEM_VERSION || beforeApp !== SOURCE_APP_VERSION) {
    fail(`unexpected source state system=${beforeSystem} app=${beforeApp}`);
  }
  step(`source=${beforeSystem}/${beforeApp}`);

  const upload = await context.post('/api/application/update/offline', {
    headers: { 'x-csrf-token': csrfToken },
    multipart: {
      metadata: {
        name: 'latest.json',
        mimeType: 'application/json',
        buffer: fs.readFileSync(process.env.APP_METADATA),
      },
      signature: {
        name: 'latest.json.sig',
        mimeType: 'application/octet-stream',
        buffer: fs.readFileSync(process.env.APP_SIGNATURE),
      },
      file: {
        name: `hardened-nanokvm-kvmapp-${APP_VERSION}.tar.gz`,
        mimeType: 'application/gzip',
        buffer: fs.readFileSync(APP_ARCHIVE),
      },
    },
    timeout: 15 * 60 * 1000,
  });
  const uploadJson = await upload.json();
  if (!upload.ok() || uploadJson?.code !== 0) fail(`offline app update failed: ${uploadJson?.msg ?? upload.status()}`);
  context = await waitCycle(context, 'app_update');
  csrfToken = await login(context, password);
  const afterApp = (await api(context, csrfToken, '/api/application/version')).current;
  if (afterApp !== APP_VERSION) fail(`app update version=${afterApp}`);
  step(`app=${afterApp}`);

  try {
    await api(context, csrfToken, '/api/vm/system/reboot', 'POST', {});
  } catch {}
  context = await waitCycle(context, 'clean_reboot');
  csrfToken = await login(context, password);
  const updateCheck = await api(context, csrfToken, '/api/system-update/check');
  if (updateCheck.error) fail(`post-reboot system update check failed: ${updateCheck.error}`);
  step('online_system_update_check=ok');

  const state = await ssh(password, `set -eu
printf 'SYSTEM=%s\\n' "$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' /etc/kvm/system-version.json | head -n 1)"
printf 'APP=%s\\n' "$(cat /kvmapp/version)"
printf 'BACKEND_DISK=%s\\n' "$(sha256sum /kvmapp/server/NanoKVM-Server | awk '{print $1}')"
printf 'BACKEND_RUNTIME=%s\\n' "$(sha256sum /tmp/server/NanoKVM-Server | awk '{print $1}')"
printf 'LIBKVM_DISK=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm.so | awk '{print $1}')"
printf 'LIBKVM_MMF_DISK=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm_mmf.so | awk '{print $1}')"
printf 'TMP_SERVER_DL_LIB=%s\\n' "$([ -e /tmp/server/dl_lib ] && echo present || echo absent)"
SYSLOG_PID="$(cat /var/run/syslogd.pid 2>/dev/null || true)"
printf 'REMOTE_SYSLOG=%s\\n' "$(tr '\\0' ' ' < "/proc/$SYSLOG_PID/cmdline" | grep -Fq -- '-R ${REMOTE_SYSLOG}' && echo active || echo missing)"
PATTERN='oops|panic|segfault|BUG:|module_put|fail to allocate ion|Invalid buffer|already inited|Unknown symbol|disagrees about version|invalid module format|VPSS.*(fail|error)|VENC.*(fail|error)'
printf 'DMESG_ALERTS=%s\\n' "$(dmesg | grep -Eic "$PATTERN" || true)"
printf 'DMESG_ALERT_LINES_BEGIN\\n'
dmesg | grep -Ei "$PATTERN" | tail -n 120 || true
printf 'DMESG_ALERT_LINES_END\\n'
`);
  fs.writeFileSync(path.join(resultDir, 'post-reboot.txt'), state, { mode: 0o600 });
  for (const expected of [
    `SYSTEM=${SYSTEM_VERSION}`, `APP=${APP_VERSION}`,
    `BACKEND_DISK=${BACKEND_SHA256}`, `BACKEND_RUNTIME=${BACKEND_SHA256}`,
    `LIBKVM_DISK=${LIBKVM_SHA256}`, `LIBKVM_MMF_DISK=${LIBKVM_MMF_SHA256}`,
    'TMP_SERVER_DL_LIB=absent', 'REMOTE_SYSLOG=active', 'DMESG_ALERTS=0',
  ]) {
    if (!state.includes(expected)) fail(`post-reboot missing ${expected}`);
  }
  step('clean_reboot_dmesg_alerts=0');
  step(`libkvm=${LIBKVM_SHA256}`);
  step(`SUCCESS: app ${APP_VERSION} installed with native fix and clean reboot baseline`);
  await context.dispose();
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
