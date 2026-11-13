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
const enduranceArg = process.argv.indexOf('--endurance-minutes');
const ENDURANCE_MINUTES = enduranceArg >= 0 ? Number(process.argv[enduranceArg + 1]) : 0;
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultPrefix = ENDURANCE_MINUTES > 0 ? `stream-endurance-${ENDURANCE_MINUTES}m` : 'stream-soak';
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `${resultPrefix}-${TARGET_IP}-${runId}`);
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

function parseFields(text) {
  const fields = new Map();
  for (const line of text.split(/\r?\n/)) {
    const index = line.indexOf('=');
    if (index > 0) fields.set(line.slice(0, index), line.slice(index + 1));
  }
  return fields;
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

async function prepareKnownHosts() {
  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fps = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fps.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
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
  const response = await context.request.post('/api/auth/login', {
    data: { username: 'admin', password: encryptPassword(password) },
    timeout: 30000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) {
    fail(`login failed: ${json?.msg ?? response.status()}`);
  }
  return json.data.csrfToken;
}

async function post(context, csrfToken, pathname, data) {
  const response = await context.request.post(pathname, {
    headers: { 'x-csrf-token': csrfToken },
    data,
    timeout: 60000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
}

async function get(context, pathname) {
  const response = await context.request.get(pathname, { timeout: 60000 });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
  return json.data;
}

async function mjpegSample(page, durationMs) {
  return page.evaluate(async (duration) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), duration);
    let bytes = 0;
    let frames = 0;
    let previous = -1;
    const prefixChunks = [];
    let prefixBytes = 0;
    try {
      const response = await fetch('/api/stream/mjpeg', { signal: controller.signal });
      if (!response.ok || !response.body) throw new Error(`MJPEG HTTP ${response.status}`);
      const reader = response.body.getReader();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (prefixBytes < 4 * 1024 * 1024) {
          const keep = value.slice(0, Math.min(value.byteLength, 4 * 1024 * 1024 - prefixBytes));
          prefixChunks.push(keep);
          prefixBytes += keep.byteLength;
        }
        for (const byte of value) {
          if (previous === 0xff && byte === 0xd8) frames += 1;
          previous = byte;
        }
      }
    } catch (error) {
      if (error.name !== 'AbortError') throw error;
    } finally {
      clearTimeout(timeout);
    }
    const prefix = new Uint8Array(prefixBytes);
    let offset = 0;
    for (const chunk of prefixChunks) {
      prefix.set(chunk, offset);
      offset += chunk.byteLength;
    }
    let width = 0;
    let height = 0;
    for (let index = 0; index + 8 < prefix.length; index += 1) {
      if (prefix[index] !== 0xff) continue;
      const marker = prefix[index + 1];
      if (![0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) continue;
      height = (prefix[index + 5] << 8) | prefix[index + 6];
      width = (prefix[index + 7] << 8) | prefix[index + 8];
      break;
    }
    return { bytes, frames, width, height };
  }, durationMs);
}

async function h264Sample(page, durationMs) {
  return page.evaluate((duration) => new Promise((resolve, reject) => {
    const socket = new WebSocket(`wss://${location.host}/api/stream/h264/direct`);
    socket.binaryType = 'arraybuffer';
    let packets = 0;
    let bytes = 0;
    const timeout = setTimeout(() => {
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
      clearTimeout(timeout);
      reject(new Error('H264 direct websocket failed'));
    };
  }), durationMs);
}

async function alertSnapshot(password, label) {
  const state = await ssh(password, `set -eu
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
test -n "$BACKEND_PID" && kill -0 "$BACKEND_PID"
KVM_COUNT=0
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in
    /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_COUNT=$((KVM_COUNT + 1)) ;;
  esac
done
PATTERN='oops|panic|segfault|BUG:|module_put|fail to allocate ion|Invalid buffer|already inited|Unknown symbol|disagrees about version|invalid module format|VPSS.*(fail|error)|VENC.*(fail|error)'
printf 'BACKEND_PID=%s\\n' "$BACKEND_PID"
printf 'KVM_SYSTEM_COUNT=%s\\n' "$KVM_COUNT"
printf 'MODULES_OK=%s\\n' "$(grep -q '^soph_vcodec ' /proc/modules && grep -q '^soph_jpeg ' /proc/modules && grep -q '^soph_vc_driver ' /proc/modules && echo yes || echo no)"
printf 'DMESG_ALERTS=%s\\n' "$(dmesg 2>/dev/null | grep -Eic "$PATTERN" || true)"
printf 'SYSLOG_ALERTS=%s\\n' "$(grep -Eic "$PATTERN" /run/hardened-syslog/messages 2>/dev/null || true)"
printf 'REMOTE_SYSLOG=%s\\n' "$(grep -Rqs '10.0.77.177' /etc 2>/dev/null && echo configured || echo not-found)"
`);
  fs.writeFileSync(path.join(resultDir, `${label}-state.txt`), state, { mode: 0o600 });
  return parseFields(state);
}

async function enduranceSoak(context, page, csrfToken, password, minutes) {
  const baseline = await alertSnapshot(password, 'endurance-baseline');
  if (baseline.get('KVM_SYSTEM_COUNT') !== '1' || baseline.get('MODULES_OK') !== 'yes') {
    fail('endurance baseline native runtime is incomplete');
  }
  const baselineDmesg = baseline.get('DMESG_ALERTS') || '0';
  const baselineSyslog = baseline.get('SYSLOG_ALERTS') || '0';
  step(`endurance_minutes=${minutes}`);
  step(`baseline_dmesg_alerts=${baselineDmesg}`);
  step(`baseline_syslog_alerts=${baselineSyslog}`);
  step(`remote_syslog=${baseline.get('REMOTE_SYSLOG') || 'unknown'}`);

  const deadline = Date.now() + minutes * 60 * 1000;
  let cycle = 0;
  let totalMjpegFrames = 0;
  let totalMjpegBytes = 0;
  let totalH264Packets = 0;
  let totalH264Bytes = 0;
  while (Date.now() < deadline) {
    cycle += 1;
    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });
    const mjpeg = await mjpegSample(page, 20000);
    if (mjpeg.frames < 5 || mjpeg.bytes < 10000) fail(`endurance_${cycle}: insufficient MJPEG data`);
    totalMjpegFrames += mjpeg.frames;
    totalMjpegBytes += mjpeg.bytes;

    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 1 });
    const h264 = await h264Sample(page, 20000);
    if (h264.packets < 5 || h264.bytes < 10000) fail(`endurance_${cycle}: insufficient H264 data`);
    totalH264Packets += h264.packets;
    totalH264Bytes += h264.bytes;
    const health = await get(context, '/api/health');
    if (health?.status !== 'ok') fail(`endurance_${cycle}: health is not ok`);
    const hdmi = await get(context, '/api/vm/hdmi');
    if (hdmi?.enabled !== true) fail(`endurance_${cycle}: HDMI disabled`);

    if (cycle === 1 || cycle % 5 === 0 || Date.now() >= deadline) {
      const snapshot = await alertSnapshot(password, `endurance-cycle-${cycle}`);
      if (snapshot.get('KVM_SYSTEM_COUNT') !== '1' || snapshot.get('MODULES_OK') !== 'yes') {
        fail(`endurance_${cycle}: native runtime changed`);
      }
      if (snapshot.get('DMESG_ALERTS') !== baselineDmesg) {
        fail(`endurance_${cycle}: dmesg alerts changed ${baselineDmesg}->${snapshot.get('DMESG_ALERTS')}`);
      }
      if (snapshot.get('SYSLOG_ALERTS') !== baselineSyslog) {
        fail(`endurance_${cycle}: syslog alerts changed ${baselineSyslog}->${snapshot.get('SYSLOG_ALERTS')}`);
      }
    }
    step(`endurance_cycle_${cycle}=mjpeg:${mjpeg.frames}/${mjpeg.bytes},h264:${h264.packets}/${h264.bytes}`);
    await sleep(5000);
  }

  await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });
  const final = await alertSnapshot(password, 'endurance-final');
  if (final.get('DMESG_ALERTS') !== baselineDmesg || final.get('SYSLOG_ALERTS') !== baselineSyslog) {
    fail('endurance final alert counts changed');
  }
  step(`endurance_cycles=${cycle}`);
  step(`total_mjpeg_frames=${totalMjpegFrames}`);
  step(`total_mjpeg_bytes=${totalMjpegBytes}`);
  step(`total_h264_packets=${totalH264Packets}`);
  step(`total_h264_bytes=${totalH264Bytes}`);
  step('SUCCESS: long MJPEG/H264 endurance and dmesg/syslog soak passed');
}

async function waitRestartCycle() {
  const probe = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true });
  let offline = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await probe.get('/api/health', { timeout: 3000 });
      if (!response.ok()) offline = true;
    } catch {
      offline = true;
    }
    if (offline) break;
    await sleep(1000);
  }
  if (!offline) {
    await probe.dispose();
    fail('backend shutdown was not observed during controlled restart');
  }
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await probe.get('/api/health', { timeout: 4000 });
      const json = await response.json();
      if (response.ok() && json?.code === 0 && json?.data?.status === 'ok') {
        await probe.dispose();
        return;
      }
    } catch {}
    await sleep(3000);
  }
  await probe.dispose();
  fail('backend did not return after controlled restart');
}

async function sampleBoth(context, page, csrfToken, label) {
  await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });
  await sleep(1000);
  const mjpeg = await mjpegSample(page, 15000);
  if (mjpeg.frames < 5 || mjpeg.bytes < 10000) fail(`${label}: insufficient MJPEG frames`);
  step(`${label}_mjpeg_frames=${mjpeg.frames}`);
  step(`${label}_mjpeg_bytes=${mjpeg.bytes}`);
  step(`${label}_mjpeg_resolution=${mjpeg.width}x${mjpeg.height}`);

  await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 1 });
  await sleep(1000);
  const h264 = await h264Sample(page, 15000);
  if (h264.packets < 5 || h264.bytes < 10000) fail(`${label}: insufficient H264 packets`);
  step(`${label}_h264_packets=${h264.packets}`);
  step(`${label}_h264_bytes=${h264.bytes}`);
}

async function resolutionSoak(context, page, csrfToken) {
  const resolutions = [
    { value: 1080, width: 1920, height: 1080 },
    { value: 720, width: 1280, height: 720 },
    { value: 600, width: 800, height: 600 },
    { value: 480, width: 640, height: 480 },
    { value: 0, width: 1920, height: 1080 },
  ];
  for (const resolution of resolutions) {
    await post(context, csrfToken, '/api/vm/screen', { type: 'resolution', value: resolution.value });
    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });
    await sleep(1000);
    const mjpeg = await mjpegSample(page, 6000);
    if (mjpeg.frames < 3 || mjpeg.bytes < 10000) fail(`resolution_${resolution.value}: insufficient MJPEG frames`);
    if (mjpeg.width !== resolution.width || mjpeg.height !== resolution.height) {
      fail(`resolution_${resolution.value}: expected ${resolution.width}x${resolution.height}, got ${mjpeg.width}x${mjpeg.height}`);
    }
    step(`resolution_${resolution.value}_mjpeg_frames=${mjpeg.frames}`);
    step(`resolution_${resolution.value}_mjpeg_bytes=${mjpeg.bytes}`);
    step(`resolution_${resolution.value}_jpeg=${mjpeg.width}x${mjpeg.height}`);

    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 1 });
    await sleep(1000);
    const h264 = await h264Sample(page, 6000);
    if (h264.packets < 3 || h264.bytes < 10000) fail(`resolution_${resolution.value}: insufficient H264 packets`);
    step(`resolution_${resolution.value}_h264_packets=${h264.packets}`);
    step(`resolution_${resolution.value}_h264_bytes=${h264.bytes}`);
  }
}

async function hdmiControlSoak(context, page, csrfToken) {
  await post(context, csrfToken, '/api/vm/hdmi/enable', {});
  if ((await get(context, '/api/vm/hdmi'))?.enabled !== true) fail('HDMI did not report enabled before reset soak');
  await post(context, csrfToken, '/api/vm/screen', { type: 'resolution', value: 0 });
  await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });

  for (let cycle = 1; cycle <= 4; cycle += 1) {
    const liveMjpeg = mjpegSample(page, 10000);
    await sleep(2500);
    await post(context, csrfToken, '/api/vm/hdmi/reset', {});
    const mjpeg = await liveMjpeg;
    if (mjpeg.frames < 3 || mjpeg.bytes < 10000) fail(`hdmi_reset_${cycle}: MJPEG did not survive reset`);
    if ((await get(context, '/api/vm/hdmi'))?.enabled !== true) fail(`hdmi_reset_${cycle}: HDMI did not return enabled`);
    step(`hdmi_reset_${cycle}_mjpeg_frames=${mjpeg.frames}`);
    step(`hdmi_reset_${cycle}_mjpeg_bytes=${mjpeg.bytes}`);

    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 1 });
    await sleep(1000);
    const h264 = await h264Sample(page, 6000);
    if (h264.packets < 3 || h264.bytes < 10000) fail(`hdmi_reset_${cycle}: insufficient H264 recovery`);
    step(`hdmi_reset_${cycle}_h264_packets=${h264.packets}`);
    step(`hdmi_reset_${cycle}_h264_bytes=${h264.bytes}`);
    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });
  }

  await post(context, csrfToken, '/api/vm/hdmi/disable', {});
  if ((await get(context, '/api/vm/hdmi'))?.enabled !== false) fail('HDMI disable state was not persisted');
  await sleep(1500);
  await post(context, csrfToken, '/api/vm/hdmi/enable', {});
  if ((await get(context, '/api/vm/hdmi'))?.enabled !== true) fail('HDMI enable state was not restored');
  await sleep(1500);
  await sampleBoth(context, page, csrfToken, 'after_hdmi_disable_enable');
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing stream soak without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  if (!Number.isInteger(ENDURANCE_MINUTES) || ENDURANCE_MINUTES < 0 || ENDURANCE_MINUTES > 240) {
    fail('invalid --endurance-minutes value');
  }
  await prepareKnownHosts();

  const browser = await chromium.launch({ headless: true, executablePath: CHROMIUM });
  let context;
  let page;
  let csrfToken;
  try {
    context = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: BASE_URL });
    page = await context.newPage();
    csrfToken = await login(context, password);
    await page.goto('/api/health', { waitUntil: 'domcontentloaded' });
    if (ENDURANCE_MINUTES > 0) {
      await enduranceSoak(context, page, csrfToken, password, ENDURANCE_MINUTES);
      return;
    }
    await sampleBoth(context, page, csrfToken, 'before_restart');

    try {
      await resolutionSoak(context, page, csrfToken);
      await hdmiControlSoak(context, page, csrfToken);
    } finally {
      try { await post(context, csrfToken, '/api/vm/hdmi/enable', {}); } catch {}
      try { await post(context, csrfToken, '/api/vm/screen', { type: 'resolution', value: 0 }); } catch {}
      try { await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 }); } catch {}
    }

    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });
    step('controlled_restart_start=yes');
    await ssh(password, "nohup sh -c 'sleep 1; /etc/init.d/S95nanokvm restart' >/tmp/hardened-restart-test.log 2>&1 </dev/null &");
    await context.close();
    context = undefined;
    await waitRestartCycle();

    context = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: BASE_URL });
    page = await context.newPage();
    csrfToken = await login(context, password);
    await page.goto('/api/health', { waitUntil: 'domcontentloaded' });
    await sampleBoth(context, page, csrfToken, 'after_restart');
    await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 });

    const finalState = await ssh(password, `set -eu
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
test -n "$BACKEND_PID" && kill -0 "$BACKEND_PID"
KVM_PID=''
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in
    /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_PID="\${PROC##*/}"; break ;;
  esac
done
test -n "$KVM_PID"
printf 'BACKEND_PID=%s\\n' "$BACKEND_PID"
printf 'KVM_SYSTEM_PID=%s\\n' "$KVM_PID"
ALERT_PATTERN='oops|panic|segfault|BUG:|module_put|fail to allocate ion|Invalid buffer|already inited|Unknown symbol|disagrees about version|invalid module format|VPSS.*(fail|error)|VENC.*(fail|error)'
printf 'DMESG_ALERTS=%s\\n' "$(dmesg 2>/dev/null | grep -Eic "$ALERT_PATTERN" || true)"
printf 'DMESG_ALERT_LINES_BEGIN\\n'
dmesg 2>/dev/null | grep -Ei "$ALERT_PATTERN" | tail -n 120 || true
printf 'DMESG_ALERT_LINES_END\\n'
printf 'RESTART_LOG_BEGIN\\n'
tail -n 80 /tmp/hardened-restart-test.log 2>/dev/null || true
printf 'RESTART_LOG_END\\n'
printf 'SERVER_LOG_BEGIN\\n'
tail -n 80 /run/nanokvm-native.log 2>/dev/null || true
printf 'SERVER_LOG_END\\n'
`);
    fs.writeFileSync(path.join(resultDir, 'final-state.txt'), finalState, { mode: 0o600 });
    if (!finalState.includes('DMESG_ALERTS=0')) fail('kernel alerts detected during stream soak');
    step('SUCCESS: resolution, HDMI control, MJPEG, H264 direct, and controlled restart soak passed');
  } finally {
    if (context) {
      try { await post(context, csrfToken, '/api/vm/hdmi/enable', {}); } catch {}
      try { await post(context, csrfToken, '/api/vm/screen', { type: 'resolution', value: 0 }); } catch {}
      try { await post(context, csrfToken, '/api/vm/screen', { type: 'type', value: 0 }); } catch {}
      try { await context.close(); } catch {}
    }
    try { await browser.close(); } catch {}
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
