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
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const EXPECTED_SYSTEM = '0.3.0-raw.5';
const SOURCE_APP = '2.0.35';
const EXPECTED_APP = '2.0.36';
const EXPECTED_KVM_SHA256 = 'f919c1b6ec1bf175d4d32b72f5ff666729422af6b2e34d23f0aa37c5193d32ef';
const EXPECTED_ARCHIVE_SHA256 = '09bf8359b37767159b68b6e7f5228e109dcf4a41981d8ca77b1f09098c884ac9';
const APP_ARCHIVE = path.join(ROOT, 'build/artifacts/nanokvm-kvmapp-rust.tar.gz');
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `kvm-watchdog-${TARGET_IP}-${runId}`);
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
      if (code !== 0) reject(new Error(`${path.basename(command)} failed with exit code ${code}`));
      else resolve(Buffer.concat(stdout));
    });
    if (secret !== undefined) child.stdio[3].end(secret);
    if (input !== undefined && child.stdin) child.stdin.end(input);
    else if (child.stdin) child.stdin.end();
  });
}

async function fileSha256(filename) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}

async function prepareKnownHosts() {
  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) fail('unexpected SSH fingerprint');
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });
}

async function ssh(password, command) {
  const output = await run(
    SSHPASS,
    [
      '-d', '3', 'ssh', '-o', 'ConnectTimeout=10', '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsPath}`,
      `root@${TARGET_IP}`, command,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
  return output.toString('utf8');
}

function encryptPassword(password) {
  return encodeURIComponent(CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString());
}

async function newContext() {
  return request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 15 * 60 * 1000 });
}

async function login(context, password) {
  const response = await context.post('/api/auth/login', {
    data: { username: 'admin', password: encryptPassword(password) },
    timeout: 30000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) fail(`login failed: ${json?.msg ?? response.status()}`);
  return json.data.csrfToken;
}

async function get(context, pathname) {
  const response = await context.get(pathname, { timeout: 30000 });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
  return json.data;
}

async function waitForCycle(oldContext) {
  let offline = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await oldContext.get('/api/health', { timeout: 3000 });
      if (!response.ok()) offline = true;
    } catch { offline = true; }
    if (offline) break;
    await sleep(1000);
  }
  await oldContext.dispose();
  if (!offline) fail('application update did not stop the old backend');

  for (let attempt = 0; attempt < 120; attempt += 1) {
    const context = await newContext();
    try {
      const response = await context.get('/api/health', { timeout: 4000 });
      const json = await response.json();
      if (response.ok() && json?.code === 0 && json?.data?.status === 'ok') return context;
    } catch {}
    await context.dispose();
    await sleep(2000);
  }
  fail('backend did not return after application update');
}

function field(text, name) {
  return text.match(new RegExp(`^${name}=([^\\r\\n]*)$`, 'm'))?.[1] || '';
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing kvm_system watchdog install without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const diagnoseOnly = process.argv.includes('--diagnose-only');
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  if (!fs.existsSync(APP_ARCHIVE)) fail('application archive is missing');
  const archiveSha = await fileSha256(APP_ARCHIVE);
  if (archiveSha !== EXPECTED_ARCHIVE_SHA256) fail(`application archive sha mismatch: ${archiveSha}`);
  step(`archive_sha256=${archiveSha}`);
  await prepareKnownHosts();

  let context = await newContext();
  let csrfToken = await login(context, password);
  const currentSystem = (await get(context, '/api/system-update/version')).current;
  const currentApp = await get(context, '/api/application/version');
  const expectedSourceApp = diagnoseOnly ? EXPECTED_APP : SOURCE_APP;
  if (currentSystem?.version !== EXPECTED_SYSTEM || currentApp?.current !== expectedSourceApp) fail('unexpected source versions');

  if (!diagnoseOnly) {
    const response = await context.post('/api/application/update/offline', {
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
          name: `hardened-nanokvm-kvmapp-${EXPECTED_APP}-kvm-watchdog.tar.gz`,
          mimeType: 'application/gzip',
          buffer: fs.readFileSync(APP_ARCHIVE),
        },
      },
      timeout: 15 * 60 * 1000,
    });
    const responseJson = await response.json();
    if (!response.ok() || responseJson?.code !== 0) fail(`offline app update failed: ${responseJson?.msg ?? response.status()}`);
    step('offline_app_update=accepted');
    context = await waitForCycle(context);
    csrfToken = await login(context, password);
  } else {
    step('offline_app_update=skipped_diagnose_only');
  }

  const afterInstall = await ssh(password, String.raw`set +e
printf 'INIT_PID_DECL=%s\n' "$(grep -q 'KVM_SYSTEM_PID_FILE=/tmp/kvm-system.pid' /kvmapp/system/init.d/S95nanokvm && echo yes || echo no)"
printf 'INIT_WATCHDOG_DECL=%s\n' "$(grep -q 'kvm_system is not running; restarting helper' /kvmapp/system/init.d/S95nanokvm && echo yes || echo no)"
printf 'INIT_BOOT_HEALTH_DECL=%s\n' "$(grep -q 'kvm_system_is_running || return 1' /kvmapp/system/init.d/S95nanokvm && echo yes || echo no)"
printf 'INIT_INSTALLED_MATCH=%s\n' "$(cmp -s /kvmapp/system/init.d/S95nanokvm /etc/init.d/S95nanokvm && echo yes || echo no)"
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
WATCHDOG_PID="$(cat /tmp/nanokvm-watchdog.pid 2>/dev/null || true)"
KVM_PID="$(cat /tmp/kvm-system.pid 2>/dev/null || true)"
printf 'BACKEND_PID=%s\n' "$BACKEND_PID"
printf 'WATCHDOG_PID=%s\n' "$WATCHDOG_PID"
printf 'KVM_SYSTEM_PID=%s\n' "$KVM_PID"
printf 'BACKEND_ALIVE=%s\n' "$([ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null && echo yes || echo no)"
printf 'WATCHDOG_ALIVE=%s\n' "$([ -n "$WATCHDOG_PID" ] && kill -0 "$WATCHDOG_PID" 2>/dev/null && echo yes || echo no)"
printf 'KVM_SYSTEM_ALIVE=%s\n' "$([ -n "$KVM_PID" ] && kill -0 "$KVM_PID" 2>/dev/null && echo yes || echo no)"
printf 'KVM_SYSTEM_SHA=%s\n' "$(sha256sum /tmp/kvm_system/kvm_system 2>/dev/null | awk '{print $1}')"
if [ -n "$KVM_PID" ] && [ -d "/proc/$KVM_PID/task" ]; then KVM_THREADS="$(find "/proc/$KVM_PID/task" -mindepth 1 -maxdepth 1 | wc -l)"; else KVM_THREADS=0; fi
printf 'KVM_SYSTEM_THREADS=%s\n' "$KVM_THREADS"
printf 'WATCHDOG_LOG_LINES=%s\n' "$(wc -l < /tmp/nanokvm-watchdog.log 2>/dev/null || echo 0)"
printf 'UDC_STATE=%s\n' "$(cat /sys/class/udc/*/state | head -n 1)"
printf 'DMESG_ALERTS=%s\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:' || true)"
`);
  fs.writeFileSync(path.join(resultDir, 'after-install.txt'), afterInstall, { mode: 0o600 });
  const backendPid = field(afterInstall, 'BACKEND_PID');
  const watchdogPid = field(afterInstall, 'WATCHDOG_PID');
  const oldKvmPid = field(afterInstall, 'KVM_SYSTEM_PID');
  const watchdogLogLines = Number(field(afterInstall, 'WATCHDOG_LOG_LINES') || '0');
  if (!backendPid || !watchdogPid || !oldKvmPid) fail('new helper watchdog did not start all processes');
  for (const expected of [
    'INIT_PID_DECL=yes', 'INIT_WATCHDOG_DECL=yes', 'INIT_BOOT_HEALTH_DECL=yes', 'INIT_INSTALLED_MATCH=yes',
    'BACKEND_ALIVE=yes', 'WATCHDOG_ALIVE=yes', 'KVM_SYSTEM_ALIVE=yes',
  ]) {
    if (!afterInstall.includes(expected)) fail(`post-install preflight missing ${expected}`);
  }
  if (field(afterInstall, 'KVM_SYSTEM_SHA') !== EXPECTED_KVM_SHA256) fail('installed kvm_system hash mismatch');
  if (!afterInstall.includes('UDC_STATE=configured') || !afterInstall.includes('DMESG_ALERTS=0')) fail('invalid post-install device state');
  step(`installed_kvm_system_pid=${oldKvmPid}`);

  await ssh(password, `set -eu
test "$(cat /tmp/kvm-system.pid)" = '${oldKvmPid}'
kill -9 '${oldKvmPid}'
`);
  step(`killed_kvm_system_pid=${oldKvmPid}`);

  let recovered = false;
  for (let attempt = 0; attempt < 25; attempt += 1) {
    await sleep(2000);
    const state = await ssh(password, `PID="$(cat /tmp/kvm-system.pid 2>/dev/null || true)"; if [ -n "$PID" ] && [ "$PID" != '${oldKvmPid}' ] && kill -0 "$PID" 2>/dev/null; then printf '%s\\n' "$PID"; fi`);
    if (/^[0-9]+\s*$/.test(state)) {
      recovered = true;
      break;
    }
  }
  if (!recovered) {
    try { await ssh(password, '/etc/init.d/S95nanokvm restart'); } catch {}
    fail('kvm_system watchdog did not recover helper within 50 seconds');
  }

  const afterRecovery = await ssh(password, String.raw`set -eu
BACKEND_PID="$(cat /tmp/nanokvm-server.pid)"
WATCHDOG_PID="$(cat /tmp/nanokvm-watchdog.pid)"
KVM_PID="$(cat /tmp/kvm-system.pid)"
kill -0 "$BACKEND_PID"
kill -0 "$WATCHDOG_PID"
kill -0 "$KVM_PID"
printf 'BACKEND_PID=%s\n' "$BACKEND_PID"
printf 'WATCHDOG_PID=%s\n' "$WATCHDOG_PID"
printf 'KVM_SYSTEM_PID=%s\n' "$KVM_PID"
printf 'KVM_SYSTEM_SHA=%s\n' "$(sha256sum /tmp/kvm_system/kvm_system | awk '{print $1}')"
printf 'KVM_SYSTEM_THREADS=%s\n' "$(find "/proc/$KVM_PID/task" -mindepth 1 -maxdepth 1 | wc -l)"
printf 'KVM_SYSTEM_LOG_ERRORS=%s\n' "$(grep -Eic 'Error loading|Error relocating|unsupported relocation' /tmp/kvm_system.log 2>/dev/null || true)"
printf 'UDC_STATE=%s\n' "$(cat /sys/class/udc/*/state | head -n 1)"
printf 'DMESG_ALERTS=%s\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:' || true)"
printf 'WATCHDOG_NEW_LOG_BEGIN\n'
sed -n '${watchdogLogLines + 1},$p' /tmp/nanokvm-watchdog.log 2>/dev/null || true
printf 'WATCHDOG_NEW_LOG_END\n'
`);
  fs.writeFileSync(path.join(resultDir, 'after-recovery.txt'), afterRecovery, { mode: 0o600 });
  const newKvmPid = field(afterRecovery, 'KVM_SYSTEM_PID');
  if (!newKvmPid || newKvmPid === oldKvmPid) fail('kvm_system PID was not replaced');
  if (field(afterRecovery, 'BACKEND_PID') !== backendPid) fail('backend restarted during helper recovery');
  if (field(afterRecovery, 'WATCHDOG_PID') !== watchdogPid) fail('watchdog restarted during helper recovery');
  if (field(afterRecovery, 'KVM_SYSTEM_SHA') !== EXPECTED_KVM_SHA256) fail('recovered helper hash mismatch');
  const threads = Number(field(afterRecovery, 'KVM_SYSTEM_THREADS') || '0');
  if (threads < 2) fail(`recovered helper thread count=${threads}`);
  for (const expected of ['KVM_SYSTEM_LOG_ERRORS=0', 'UDC_STATE=configured', 'DMESG_ALERTS=0']) {
    if (!afterRecovery.includes(expected)) fail(`helper recovery missing ${expected}`);
  }
  if (!afterRecovery.includes('kvm_system is not running; restarting helper') || !afterRecovery.includes('started kvm_system pid')) {
    fail('helper watchdog recovery was not logged');
  }
  await get(context, '/api/health');
  await context.dispose();
  step(`recovered_kvm_system_pid=${newKvmPid}`);
  step(`backend_pid_unchanged=${backendPid}`);
  step(`watchdog_pid_unchanged=${watchdogPid}`);
  step('SUCCESS: offline app update and kvm_system SIGKILL recovery passed');
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
