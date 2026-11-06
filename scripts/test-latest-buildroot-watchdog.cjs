#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const CryptoJS = require('../web/node_modules/crypto-js');
const { request } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const BASE_URL = `https://${TARGET_IP}`;
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `watchdog-drill-${TARGET_IP}-${runId}`);
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

async function prepareKnownHosts() {
  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    fail('unexpected SSH fingerprint');
  }
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

async function login(context, password) {
  const response = await context.post('/api/auth/login', {
    data: { username: 'admin', password: encryptPassword(password) },
    timeout: 30000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) fail(`login failed: ${json?.msg ?? response.status()}`);
  return json.data.csrfToken;
}

async function post(context, csrfToken, pathname, data) {
  const response = await context.post(pathname, {
    headers: { 'x-csrf-token': csrfToken },
    data,
    timeout: 30000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
}

async function waitForHealth() {
  const context = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 10000 });
  try {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        const response = await context.get('/api/health', { timeout: 4000 });
        const json = await response.json();
        if (response.ok() && json?.code === 0 && json?.data?.status === 'ok') return;
      } catch {}
      await sleep(2000);
    }
  } finally {
    await context.dispose();
  }
  fail('backend watchdog did not restore health within 60 seconds');
}

function field(text, name) {
  return text.match(new RegExp(`^${name}=([^\\r\\n]*)$`, 'm'))?.[1] || '';
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing watchdog drill without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  await prepareKnownHosts();

  const before = await ssh(password, String.raw`set -eu
BACKEND_PID="$(cat /tmp/nanokvm-server.pid)"
WATCHDOG_PID="$(/usr/libexec/nanokvm-native-ctl --watchdog status runtime)"
KVM_PID=''
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_PID="$(basename "$PROC")"; break ;; esac
done
kill -0 "$BACKEND_PID"
kill -0 "$WATCHDOG_PID"
kill -0 "$KVM_PID"
printf 'BACKEND_PID=%s\n' "$BACKEND_PID"
printf 'WATCHDOG_PID=%s\n' "$WATCHDOG_PID"
printf 'KVM_SYSTEM_PID=%s\n' "$KVM_PID"
printf 'WATCHDOG_LOG_LINES=%s\n' "$(wc -l < /run/nanokvm-watchdog.log 2>/dev/null || echo 0)"
printf 'UDC_STATE=%s\n' "$(cat /sys/class/udc/*/state | head -n 1)"
kill -9 "$BACKEND_PID"
`);
  fs.writeFileSync(path.join(resultDir, 'before.txt'), before, { mode: 0o600 });
  const oldBackendPid = field(before, 'BACKEND_PID');
  const watchdogPid = field(before, 'WATCHDOG_PID');
  const kvmPid = field(before, 'KVM_SYSTEM_PID');
  const watchdogLogLines = Number(field(before, 'WATCHDOG_LOG_LINES') || '0');
  if (!oldBackendPid || !watchdogPid || !kvmPid || !before.includes('UDC_STATE=configured')) fail('invalid watchdog preflight');
  step(`killed_backend_pid=${oldBackendPid}`);

  try {
    await waitForHealth();
  } catch (error) {
    try { await ssh(password, '/etc/init.d/S95nanokvm restart-server'); } catch {}
    throw error;
  }

  const context = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 30000 });
  try {
    const csrfToken = await login(context, password);
    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 1 });
    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });
  } finally {
    await context.dispose();
  }

  const after = await ssh(password, String.raw`set -eu
BACKEND_PID="$(cat /tmp/nanokvm-server.pid)"
WATCHDOG_PID="$(/usr/libexec/nanokvm-native-ctl --watchdog status runtime)"
KVM_PID=''
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_PID="$(basename "$PROC")"; break ;; esac
done
kill -0 "$BACKEND_PID"
kill -0 "$WATCHDOG_PID"
kill -0 "$KVM_PID"
printf 'BACKEND_PID=%s\n' "$BACKEND_PID"
printf 'WATCHDOG_PID=%s\n' "$WATCHDOG_PID"
printf 'KVM_SYSTEM_PID=%s\n' "$KVM_PID"
printf 'H264_SAFE_MODE=%s\n' "$([ -e /etc/kvm/h264_safe_mode ] && echo present || echo cleared)"
printf 'STREAM_TYPE=%s\n' "$(cat /kvmapp/kvm/type)"
printf 'UDC_STATE=%s\n' "$(cat /sys/class/udc/*/state | head -n 1)"
printf 'DMESG_ALERTS=%s\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:' || true)"
printf 'WATCHDOG_NEW_LOG_BEGIN\n'
sed -n '${watchdogLogLines + 1},$p' /run/nanokvm-watchdog.log 2>/dev/null || true
printf 'WATCHDOG_NEW_LOG_END\n'
`);
  fs.writeFileSync(path.join(resultDir, 'after.txt'), after, { mode: 0o600 });
  const newBackendPid = field(after, 'BACKEND_PID');
  if (!newBackendPid || newBackendPid === oldBackendPid) fail('backend PID was not replaced');
  if (field(after, 'WATCHDOG_PID') !== watchdogPid) fail('watchdog PID changed during backend recovery');
  if (field(after, 'KVM_SYSTEM_PID') !== kvmPid) fail('kvm_system PID changed during backend recovery');
  for (const expected of ['H264_SAFE_MODE=cleared', 'STREAM_TYPE=mjpeg', 'UDC_STATE=configured', 'DMESG_ALERTS=0']) {
    if (!after.includes(expected)) fail(`watchdog postflight missing ${expected}`);
  }
  if (!after.includes('NanoKVM-Server is not running; restarting in MJPEG safe mode')) {
    fail('watchdog restart reason was not logged');
  }
  step(`recovered_backend_pid=${newBackendPid}`);
  step(`watchdog_pid_unchanged=${watchdogPid}`);
  step(`kvm_system_pid_unchanged=${kvmPid}`);
  step('SUCCESS: backend SIGKILL was recovered automatically in MJPEG safe mode');
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
