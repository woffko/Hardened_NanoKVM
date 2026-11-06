#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const CryptoJS = require('../web/node_modules/crypto-js');
const { chromium, request } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const BASE_URL = `https://${TARGET_IP}`;
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const CHROMIUM = '/home/w0w/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome';
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const labelIndex = process.argv.indexOf('--label');
const expectIndex = process.argv.indexOf('--expect');
const label = labelIndex >= 0 ? process.argv[labelIndex + 1] : '';
const expectation = expectIndex >= 0 ? process.argv[expectIndex + 1] : '';
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `physical-hdmi-${label}-${TARGET_IP}-${runId}`);
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

async function login(context, password) {
  const response = await context.post('/api/auth/login', {
    data: { username: 'admin', password: encryptPassword(password) },
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) fail('API login failed');
  return json.data.csrfToken;
}

async function post(context, csrfToken, pathname, data) {
  const response = await context.post(pathname, {
    headers: { 'x-csrf-token': csrfToken },
    data,
    timeout: 60000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
}

async function mjpegSample(page, durationMs) {
  return page.evaluate(async (duration) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), duration);
    let bytes = 0;
    let frames = 0;
    let previous = -1;
    try {
      const response = await fetch('/api/stream/mjpeg', { signal: controller.signal });
      if (!response.ok || !response.body) throw new Error(`MJPEG HTTP ${response.status}`);
      const reader = response.body.getReader();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        for (const byte of value) {
          if (previous === 0xff && byte === 0xd8) frames += 1;
          previous = byte;
        }
      }
    } catch (error) {
      if (error.name !== 'AbortError') throw error;
    } finally {
      clearTimeout(timer);
    }
    return { bytes, frames };
  }, durationMs);
}

async function h264Sample(page, durationMs) {
  return page.evaluate((duration) => new Promise((resolve, reject) => {
    const socket = new WebSocket(`wss://${location.host}/api/stream/h264/direct`);
    socket.binaryType = 'arraybuffer';
    let packets = 0;
    let bytes = 0;
    const timer = setTimeout(() => {
      socket.close();
      resolve({ packets, bytes });
    }, duration);
    socket.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        packets += 1;
        bytes += event.data.byteLength;
      }
    };
    socket.onerror = () => {
      clearTimeout(timer);
      reject(new Error('H264 websocket failed'));
    };
  }), durationMs);
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing physical HDMI capture without --confirm-device ${TARGET_IP}`);
  }
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(label)) fail('invalid phase label');
  if (!['active', 'inactive'].includes(expectation)) fail('invalid --expect value');
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    fail('unexpected SSH fingerprint');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });

  const api = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 60000 });
  await login(api, password);
  const healthResponse = await api.get('/api/health');
  const health = await healthResponse.json();
  if (!healthResponse.ok() || health?.data?.status !== 'ok') fail('health API is not ok');
  const hdmiResponse = await api.get('/api/vm/hdmi');
  const hdmi = await hdmiResponse.json();
  if (!hdmiResponse.ok() || hdmi?.code !== 0 || hdmi?.data?.enabled !== true) fail('HDMI API is disabled');
  step('api_health=ok');
  step('hdmi_enabled=true');

  if (expectation === 'active') {
    const browser = await chromium.launch({ headless: true, executablePath: CHROMIUM });
    try {
      const context = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: BASE_URL });
      const page = await context.newPage();
      const browserCsrfToken = await login(context.request, password);
      await page.goto('/api/health', { waitUntil: 'domcontentloaded' });
      await post(context.request, browserCsrfToken, '/api/vm/screen', { type: 'resolution', value: 0 });
      await post(context.request, browserCsrfToken, '/api/vm/screen', { type: 'type', value: 0 });
      const mjpeg = await mjpegSample(page, 6000);
      if (mjpeg.frames < 3 || mjpeg.bytes < 10000) fail('active phase has insufficient MJPEG data');
      await post(context.request, browserCsrfToken, '/api/vm/screen', { type: 'type', value: 1 });
      const h264 = await h264Sample(page, 6000);
      if (h264.packets < 3 || h264.bytes < 10000) fail('active phase has insufficient H264 data');
      await post(context.request, browserCsrfToken, '/api/vm/screen', { type: 'type', value: 0 });
      step(`mjpeg=${mjpeg.frames}/${mjpeg.bytes}`);
      step(`h264=${h264.packets}/${h264.bytes}`);
      await context.close();
    } finally {
      await browser.close();
    }
  } else {
    await sleep(6000);
  }
  await api.dispose();

  const state = (await run(
    SSHPASS,
    [
      '-d', '3', 'ssh', '-o', 'ConnectTimeout=10', '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsPath}`,
      `root@${TARGET_IP}`,
      `set -eu
sleep 6
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
KVM_COUNT=0
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_COUNT=$((KVM_COUNT + 1));; esac
done
HDMI_BLOCK="$(sed -n '/"hdmi"[[:space:]]*:/,/^[[:space:]]*},/p' /run/nanokvm-hwmon-state.json 2>/dev/null || true)"
printf 'BACKEND_RUNNING=%s\\n' "$([ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null && echo yes || echo no)"
printf 'KVM_SYSTEM_COUNT=%s\\n' "$KVM_COUNT"
printf 'HWMON_ACTIVE=%s\\n' "$(printf '%s\\n' "$HDMI_BLOCK" | sed -n 's/.*"active"[[:space:]]*:[[:space:]]*\\([^,]*\\).*/\\1/p' | tr -d ' ')"
printf 'HWMON_VI_FPS=%s\\n' "$(printf '%s\\n' "$HDMI_BLOCK" | sed -n 's/.*"vi_fps"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')"
printf 'STREAM_WIDTH=%s\\n' "$(cat /kvmapp/kvm/width 2>/dev/null || true)"
printf 'STREAM_HEIGHT=%s\\n' "$(cat /kvmapp/kvm/height 2>/dev/null || true)"
printf 'VI_DBG=%s\\n' "$(grep 'VIFPS' /proc/cvitek/vi_dbg 2>/dev/null | head -n 1)"
SYSLOG_PID="$(cat /var/run/syslogd.pid 2>/dev/null || true)"
printf 'REMOTE_SYSLOG=%s\\n' "$(tr '\\0' ' ' < "/proc/$SYSLOG_PID/cmdline" 2>/dev/null | grep -Fq -- '-R 10.0.77.177:514' && echo active || echo missing)"
PATTERN='oops|panic|segfault|BUG:|module_put|fail to allocate ion|Invalid buffer|already inited|Unknown symbol|disagrees about version|invalid module format|VPSS.*(fail|error)|VENC.*(fail|error)'
printf 'DMESG_ALERTS=%s\\n' "$(dmesg | grep -Eic "$PATTERN" || true)"
printf 'SYSLOG_ALERTS=%s\\n' "$(grep -Eic "$PATTERN" /run/hardened-syslog/messages 2>/dev/null || true)"
printf 'DMESG_ALERT_LINES_BEGIN\\n'
dmesg | grep -Ei "$PATTERN" | tail -n 120 || true
printf 'DMESG_ALERT_LINES_END\\n'
`,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  )).toString('utf8');
  fs.writeFileSync(path.join(resultDir, 'state.txt'), state, { mode: 0o600 });
  const active = state.match(/^HWMON_ACTIVE=(.*)$/m)?.[1] || '';
  if (expectation === 'active' && active !== 'true') fail(`expected active HDMI, got ${active || 'missing'}`);
  if (expectation === 'inactive' && !['false', 'null'].includes(active)) fail(`expected inactive HDMI, got ${active || 'missing'}`);
  for (const expected of ['BACKEND_RUNNING=yes', 'KVM_SYSTEM_COUNT=1', 'REMOTE_SYSLOG=active', 'DMESG_ALERTS=0', 'SYSLOG_ALERTS=0']) {
    if (!state.includes(expected)) fail(`state missing ${expected}`);
  }
  step(`hwmon_active=${active}`);
  step(`hwmon_vi_fps=${state.match(/^HWMON_VI_FPS=(.*)$/m)?.[1] || ''}`);
  step(`stream_resolution=${state.match(/^STREAM_WIDTH=(.*)$/m)?.[1] || ''}x${state.match(/^STREAM_HEIGHT=(.*)$/m)?.[1] || ''}`);
  step(`SUCCESS: physical HDMI phase ${label} matched ${expectation}`);
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
