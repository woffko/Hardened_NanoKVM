#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const CryptoJS = require('../web/node_modules/crypto-js');
const { request } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const EXPECTED_SYSTEM = process.env.EXPECTED_SYSTEM_VERSION || '0.3.0-raw.10';
const EXPECTED_APP = process.env.EXPECTED_APP_VERSION || '2.0.40';
const EXPECTED_HOSTNAME = process.env.EXPECTED_HOSTNAME || 'secondary';
const EXPECTED_BACKEND_SHA256 = process.env.EXPECTED_BACKEND_SHA256
  || '04e50160903434a1086ae337c3522ea93c1f2292e01833ca24db1de70882bdb4';
const EXPECTED_KVM_SYSTEM_SHA256 = process.env.EXPECTED_KVM_SYSTEM_SHA256
  || 'f919c1b6ec1bf175d4d32b72f5ff666729422af6b2e34d23f0aa37c5193d32ef';
const EXPECTED_LIBKVM_SHA256 = process.env.EXPECTED_LIBKVM_SHA256
  || '387f1c7f54fb67ecc0eafa961946eef7972022a92ad443fb68c3d88ef6d2f24f';
const EXPECTED_LIBKVM_MMF_SHA256 = process.env.EXPECTED_LIBKVM_MMF_SHA256
  || 'be269c595b454930abeb9bb05eb67ec708894eb2df1650c4d99ee1162e1e3f2d';
const EXPECTED_S30ETH_SHA256 = process.env.EXPECTED_S30ETH_SHA256
  || '55b94ccb2ae9d1143eb4028a08c72f66bcd59b693599b39b39498f69b4642b77';
const EXPECTED_SOPH_VCODEC_SHA256 = process.env.EXPECTED_SOPH_VCODEC_SHA256
  || '0f0927cd796275f2241e8914b3efa57b124b8cc2aabc087ee899a56346a5c2be';
const EXPECTED_SOPH_JPEG_SHA256 = process.env.EXPECTED_SOPH_JPEG_SHA256
  || 'eacf2af2c75c23816af129843912f5072c9cb81d44434d563ceb449ee2899666';
const EXPECTED_SOPH_VC_DRIVER_SHA256 = process.env.EXPECTED_SOPH_VC_DRIVER_SHA256
  || 'cc543c2a1b25c63c0372d7a687643605b1d07a5624403e3cf7d74b52ecadecf5';
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `reboot-soak-${EXPECTED_SYSTEM}-${TARGET_IP}-${runId}`);
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

async function prepareKnownHosts() {
  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    fail('unexpected initial SSH fingerprint');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });
}

async function ssh(password, command) {
  const output = await run(
    SSHPASS,
    [
      '-d', '3', 'ssh', '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
      '-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'PubkeyAuthentication=no',
      '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsPath}`,
      `root@${TARGET_IP}`, command,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
  return output.toString('utf8');
}

async function newContext() {
  return request.newContext({
    baseURL: `https://${TARGET_IP}`,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Accept: 'application/json' },
    timeout: 60000,
  });
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
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) {
    fail(`login failed: ${json?.msg ?? response.status()}`);
  }
  return json.data.csrfToken;
}

async function api(context, csrfToken, pathname, method = 'GET', body = undefined) {
  const response = await context.fetch(pathname, {
    method,
    data: body,
    headers: method === 'GET' ? {} : { 'x-csrf-token': csrfToken },
    timeout: 60000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data && method === 'GET') {
    fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
  }
  return json.data;
}

async function waitForReboot(oldContext, cycle) {
  let offline = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await oldContext.get('/api/health', { timeout: 3000 });
      if (!response.ok()) offline = true;
    } catch {
      offline = true;
    }
    if (offline) break;
    await sleep(2000);
  }
  await oldContext.dispose();
  if (!offline) step(`cycle_${cycle}_offline_not_observed=yes`);

  for (let attempt = 0; attempt < 180; attempt += 1) {
    const context = await newContext();
    try {
      const response = await context.get('/api/health', { timeout: 4000 });
      const json = await response.json();
      if (response.ok() && json?.code === 0 && json?.data?.status === 'ok') return context;
    } catch {}
    await context.dispose();
    await sleep(5000);
  }
  fail(`cycle ${cycle}: HTTPS did not return`);
}

async function verifyCycle(context, password, cycle) {
  const csrfToken = await login(context, password);
  const version = (await api(context, csrfToken, '/api/system-update/version')).current;
  const app = await api(context, csrfToken, '/api/application/version');
  const status = await api(context, csrfToken, '/api/system-update/status');
  const raw = await api(context, csrfToken, '/api/system-update/raw-enabled');
  const check = await api(context, csrfToken, '/api/system-update/check');
  await api(context, csrfToken, '/api/vm/hdmi');
  if (version.version !== EXPECTED_SYSTEM) fail(`cycle ${cycle}: system=${version.version}`);
  if (app.current !== EXPECTED_APP) fail(`cycle ${cycle}: app=${app.current}`);
  if (status.pending) fail(`cycle ${cycle}: pending update remains`);
  if (raw.enabled !== false) fail(`cycle ${cycle}: raw updates enabled`);
  if (check.error) fail(`cycle ${cycle}: update check error=${check.error}`);

  const sshState = await ssh(password, `set -eu
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
test -n "$BACKEND_PID" && kill -0 "$BACKEND_PID"
KVM_PID=''
KVM_PROCESS_COUNT=0
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in
    /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_PROCESS_COUNT=$((KVM_PROCESS_COUNT + 1)); KVM_PID="\${PROC##*/}" ;;
  esac
done
test -n "$KVM_PID"
printf 'HOSTNAME=%s\\n' "$(hostname)"
printf 'HOSTNAME_FILE=%s\\n' "$(head -n 1 /etc/hostname | tr -d '\\r\\n')"
printf 'PROTO=%s\\n' "$(awk -F: '/^[[:space:]]*proto:/ { value=$2; gsub(/[[:space:]\"]/, "", value); print value; exit }' /etc/kvm/server.yaml)"
printf 'BACKEND_PID=%s\\n' "$BACKEND_PID"
printf 'BACKEND_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/NanoKVM-Server | awk '{print $1}')"
printf 'BACKEND_RUNTIME_SHA=%s\\n' "$(sha256sum /tmp/server/NanoKVM-Server | awk '{print $1}')"
printf 'LIBKVM_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm.so | awk '{print $1}')"
printf 'LIBKVM_MMF_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm_mmf.so | awk '{print $1}')"
printf 'TMP_SERVER_DL_LIB=%s\\n' "$([ -e /tmp/server/dl_lib ] && echo present || echo absent)"
printf 'KVM_SYSTEM_PID=%s\\n' "$KVM_PID"
printf 'KVM_SYSTEM_PID_FILE=%s\\n' "$(cat /tmp/kvm-system.pid 2>/dev/null || true)"
printf 'KVM_SYSTEM_PROCESS_COUNT=%s\\n' "$KVM_PROCESS_COUNT"
printf 'KVM_SYSTEM_THREADS=%s\\n' "$(find "/proc/$KVM_PID/task" -mindepth 1 -maxdepth 1 | wc -l)"
printf 'KVM_SYSTEM_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/kvm_system/kvm_system | awk '{print $1}')"
printf 'KVM_SYSTEM_RUNTIME_SHA=%s\\n' "$(sha256sum /tmp/kvm_system/kvm_system | awk '{print $1}')"
printf 'S30ETH_SHA=%s\\n' "$(sha256sum /etc/init.d/S30eth | awk '{print $1}')"
printf 'KVMAPP_S30ETH_SHA=%s\\n' "$(sha256sum /kvmapp/system/init.d/S30eth | awk '{print $1}')"
printf 'SOPH_VCODEC_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_vcodec.ko | awk '{print $1}')"
printf 'SOPH_JPEG_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_jpeg.ko | awk '{print $1}')"
printf 'SOPH_VC_DRIVER_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_vc_driver.ko | awk '{print $1}')"
printf 'MODULE_VCODEC=%s\\n' "$(grep -q '^soph_vcodec ' /proc/modules && echo loaded || echo missing)"
printf 'MODULE_JPEG=%s\\n' "$(grep -q '^soph_jpeg ' /proc/modules && echo loaded || echo missing)"
printf 'MODULE_VC_DRIVER=%s\\n' "$(grep -q '^soph_vc_driver ' /proc/modules && echo loaded || echo missing)"
printf 'DNS_TOTAL=%s\\n' "$(awk '$1 == \"nameserver\" { count++ } END { print count + 0 }' /etc/resolv.conf)"
printf 'DNS_UNIQUE=%s\\n' "$(awk '$1 == \"nameserver\" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
/lib/ld-musl-riscv64v0p7_xthead.so.1 --library-path \
  /kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd \
  --list /tmp/kvm_system/kvm_system >/tmp/hardened-kvm-system-reboot-soak.txt 2>&1
printf 'KVM_SYSTEM_LIST_RC=0\\n'
printf 'KVM_SYSTEM_LOG_ERRORS=%s\\n' "$(grep -Eic 'Error loading|Error relocating|unsupported relocation' /tmp/kvm_system.log 2>/dev/null || true)"
printf 'BOOT_GOOD=%s\\n' "$([ -e /etc/kvm/system-update-boot-good.json ] && echo present || echo missing)"
printf 'RAW_MARKER=%s\\n' "$([ -e /data/hardened-system-raw-update-pending.json ] && echo present || echo cleared)"
printf 'UDC_STATE=%s\\n' "$(cat /sys/class/udc/*/state 2>/dev/null | head -n 1)"
printf 'LUN_FILE=%s\\n' "$(cat /sys/kernel/config/usb_gadget/g0/functions/mass_storage.disk0/lun.0/file 2>/dev/null || true)"
printf 'DMESG_ALERTS=%s\\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format' || true)"
`);
  for (const expected of [
    `HOSTNAME=${EXPECTED_HOSTNAME}`, `HOSTNAME_FILE=${EXPECTED_HOSTNAME}`, 'PROTO=https',
    `BACKEND_DISK_SHA=${EXPECTED_BACKEND_SHA256}`,
    `BACKEND_RUNTIME_SHA=${EXPECTED_BACKEND_SHA256}`,
    `KVM_SYSTEM_DISK_SHA=${EXPECTED_KVM_SYSTEM_SHA256}`,
    `KVM_SYSTEM_RUNTIME_SHA=${EXPECTED_KVM_SYSTEM_SHA256}`,
    `LIBKVM_DISK_SHA=${EXPECTED_LIBKVM_SHA256}`,
    `LIBKVM_MMF_DISK_SHA=${EXPECTED_LIBKVM_MMF_SHA256}`,
    'TMP_SERVER_DL_LIB=absent',
    `S30ETH_SHA=${EXPECTED_S30ETH_SHA256}`, `KVMAPP_S30ETH_SHA=${EXPECTED_S30ETH_SHA256}`,
    `SOPH_VCODEC_SHA=${EXPECTED_SOPH_VCODEC_SHA256}`,
    `SOPH_JPEG_SHA=${EXPECTED_SOPH_JPEG_SHA256}`,
    `SOPH_VC_DRIVER_SHA=${EXPECTED_SOPH_VC_DRIVER_SHA256}`,
    'MODULE_VCODEC=loaded', 'MODULE_JPEG=loaded', 'MODULE_VC_DRIVER=loaded',
    'KVM_SYSTEM_PROCESS_COUNT=1', 'KVM_SYSTEM_LIST_RC=0', 'KVM_SYSTEM_LOG_ERRORS=0',
    'BOOT_GOOD=present', 'RAW_MARKER=cleared', 'UDC_STATE=configured',
    'LUN_FILE=/dev/mmcblk0p3', 'DMESG_ALERTS=0',
  ]) {
    if (!sshState.includes(expected)) fail(`cycle ${cycle}: missing ${expected}`);
  }
  const kvmThreads = Number(sshState.match(/^KVM_SYSTEM_THREADS=([0-9]+)$/m)?.[1] || '0');
  if (kvmThreads < 2) fail(`cycle ${cycle}: kvm_system thread count=${kvmThreads}`);
  const kvmPid = sshState.match(/^KVM_SYSTEM_PID=([0-9]+)$/m)?.[1] || '';
  const kvmPidFile = sshState.match(/^KVM_SYSTEM_PID_FILE=([0-9]+)$/m)?.[1] || '';
  if (!kvmPid || kvmPidFile !== kvmPid) fail(`cycle ${cycle}: kvm_system PID file mismatch`);
  const dnsTotal = sshState.match(/^DNS_TOTAL=([0-9]+)$/m)?.[1] || '';
  const dnsUnique = sshState.match(/^DNS_UNIQUE=([0-9]+)$/m)?.[1] || '';
  if (!dnsTotal || dnsTotal !== dnsUnique) fail(`cycle ${cycle}: DNS duplicates ${dnsTotal}/${dnsUnique}`);
  fs.writeFileSync(path.join(resultDir, `cycle-${cycle}.txt`), sshState, { mode: 0o600 });
  step(`cycle_${cycle}=passed`);
  return csrfToken;
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing reboot soak without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  await prepareKnownHosts();

  let context = await newContext();
  let csrfToken = await verifyCycle(context, password, 0);
  for (let cycle = 1; cycle <= 5; cycle += 1) {
    step(`cycle_${cycle}_reboot_start=yes`);
    try {
      await api(context, csrfToken, '/api/vm/system/reboot', 'POST', {});
    } catch (error) {
      step(`cycle_${cycle}_reboot_disconnect=${error.name}`);
    }
    context = await waitForReboot(context, cycle);
    csrfToken = await verifyCycle(context, password, cycle);
  }
  await context.dispose();
  step('SUCCESS: five reboot cycles passed');
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
