#!/usr/bin/env node

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const CryptoJS = require('../web/node_modules/crypto-js');
const { chromium } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const BASE_URL = `https://${TARGET_IP}`;
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const MKFS_FAT = path.join(ROOT, 'build/host-deps/usr/sbin/mkfs.fat');
const CHROMIUM = '/home/w0w/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome';
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `usb-safe-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');
const knownHostsPath = path.join(resultDir, 'known_hosts');
const imageName = `hardened-usb-safe-${runId}.img`;
const imagePath = path.join(resultDir, imageName);
const remoteImagePath = `/data/${imageName}`;

function step(message) {
  fs.appendFileSync(reportPath, `${new Date().toISOString()} ${message}\n`, { mode: 0o600 });
}

function fail(message) {
  throw new Error(message);
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
        error.stderr = Buffer.concat(stderr).toString('utf8');
        reject(error);
      } else {
        resolve(Buffer.concat(stdout));
      }
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

async function api(context, csrfToken, pathname, method = 'GET', data = undefined) {
  const response = await context.request.fetch(pathname, {
    method,
    data,
    headers: method === 'GET' ? {} : { 'x-csrf-token': csrfToken },
    timeout: 120000,
  });
  const responseText = await response.text();
  let json;
  try {
    json = JSON.parse(responseText);
  } catch {
    fail(`${method} ${pathname} returned non-JSON status ${response.status()} (${responseText.length} bytes)`);
  }
  if (!response.ok() || json?.code !== 0) {
    fail(`${method} ${pathname} failed: ${json?.msg ?? response.status()}`);
  }
  return json.data;
}

async function uploadImage(context, csrfToken) {
  const response = await context.request.post('/api/download/file', {
    headers: { 'x-csrf-token': csrfToken },
    multipart: {
      file: {
        name: imageName,
        mimeType: 'application/octet-stream',
        buffer: fs.readFileSync(imagePath),
      },
    },
    timeout: 120000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) {
    fail(`virtual media upload failed: ${json?.msg ?? response.status()}`);
  }
}

async function ejectWithExplicitReconnect(context, csrfToken, label) {
  await api(context, csrfToken, '/api/storage/usb/reconnect', 'POST', {});
  await api(context, csrfToken, '/api/storage/image/mount', 'POST', { file: '', cdrom: false });
  step(`${label}_explicit_usb_reconnect=yes`);
}

async function sendZeroHidReports(page) {
  return page.evaluate(() => new Promise((resolve, reject) => {
    const socket = new WebSocket(`wss://${location.host}/api/ws`);
    socket.binaryType = 'arraybuffer';
    let messages = 0;
    let opened = false;
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error('HID websocket timed out'));
    }, 10000);
    socket.onmessage = () => { messages += 1; };
    socket.onerror = () => {
      clearTimeout(timer);
      reject(new Error('HID websocket failed'));
    };
    socket.onopen = () => {
      opened = true;
      socket.send(new Uint8Array([0]));
      socket.send(new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0]));
      socket.send(new Uint8Array([2, 0, 0, 0, 0]));
      socket.send(new Uint8Array([2, 0, 0, 0, 0, 0, 0]));
      setTimeout(() => socket.close(), 1500);
    };
    socket.onclose = () => {
      clearTimeout(timer);
      resolve({ opened, messages });
    };
  }));
}

const inventoryCommand = String.raw`set -eu
G=/sys/kernel/config/usb_gadget/g0
topology_hash() {
  {
    for P in "$G/functions"/*; do [ -e "$P" ] && printf 'F:%s\n' "\${P##*/}"; done
    for P in "$G/configs/c.1"/*; do [ -L "$P" ] && printf 'L:%s:%s\n' "\${P##*/}" "$(readlink "$P")"; done
  } | sort | sha256sum | awk '{print $1}'
}
printf 'TOPOLOGY_SHA=%s\n' "$(topology_hash)"
printf 'UDC=%s\n' "$(cat "$G/UDC")"
for U in /sys/class/udc/*; do [ -e "$U" ] && printf 'UDC_STATE=%s\n' "$(cat "$U/state")"; done
for N in 0 1 2; do
  if [ -c "/dev/hidg$N" ]; then
    printf 'HIDG%s=char:%s\n' "$N" "$(stat -c '%a:%t:%T' "/dev/hidg$N")"
  else
    printf 'HIDG%s=missing\n' "$N"
  fi
done
for F in hid.GS0 hid.GS1 hid.GS2; do
  D="$G/functions/$F"
  if [ -d "$D" ]; then
    printf '%s_REPORT_LENGTH=%s\n' "$F" "$(cat "$D/report_length")"
    printf '%s_REPORT_DESC_BYTES=%s\n' "$F" "$(wc -c < "$D/report_desc")"
  else
    printf '%s=missing\n' "$F"
  fi
done
if [ -d "$G/functions/mass_storage.disk0/lun.0" ]; then
  L="$G/functions/mass_storage.disk0/lun.0"
  printf 'MASS_STORAGE=present\n'
  printf 'LUN_FILE=%s\n' "$(cat "$L/file")"
  printf 'LUN_CDROM=%s\n' "$(cat "$L/cdrom")"
  printf 'LUN_RO=%s\n' "$(cat "$L/ro")"
else
  printf 'MASS_STORAGE=missing\n'
fi
printf 'RNDIS=%s\n' "$([ -d "$G/functions/rndis.usb0" ] && echo present || echo missing)"
printf 'NCM=%s\n' "$([ -d "$G/functions/ncm.usb0" ] && echo present || echo missing)"
printf 'ACM=%s\n' "$([ -d "$G/functions/acm.GS0" ] && echo present || echo missing)"
printf 'SERVER_LOG_LINES=%s\n' "$(wc -l < /run/nanokvm-native.log 2>/dev/null || echo 0)"
printf 'DMESG_ALERTS=%s\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:' || true)"
`;

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing USB test without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  for (const file of [SSHPASS, MKFS_FAT, CHROMIUM]) {
    if (!fs.existsSync(file)) fail(`missing local dependency: ${file}`);
  }
  await prepareKnownHosts();

  const fd = fs.openSync(imagePath, 'w', 0o600);
  fs.ftruncateSync(fd, 8 * 1024 * 1024);
  fs.closeSync(fd);
  await run(MKFS_FAT, ['-n', 'HARDENED', imagePath]);
  const imageSha = crypto.createHash('sha256').update(fs.readFileSync(imagePath)).digest('hex');
  step(`test_image=${imageName}`);
  step(`test_image_sha256=${imageSha}`);

  const beforeInventory = await ssh(password, inventoryCommand);
  fs.writeFileSync(path.join(resultDir, 'before.txt'), beforeInventory, { mode: 0o600 });
  const topologyBefore = beforeInventory.match(/^TOPOLOGY_SHA=([0-9a-f]{64})$/m)?.[1] || '';
  const logLines = Number(beforeInventory.match(/^SERVER_LOG_LINES=([0-9]+)$/m)?.[1] || '0');
  for (const expected of [
    'UDC_STATE=configured', 'HIDG0=char:', 'HIDG1=char:', 'HIDG2=char:',
    'hid.GS0_REPORT_LENGTH=8', 'hid.GS1_REPORT_LENGTH=4', 'hid.GS2_REPORT_LENGTH=6',
    'MASS_STORAGE=present', 'LUN_CDROM=0', 'DMESG_ALERTS=0',
  ]) {
    if (!beforeInventory.includes(expected)) fail(`USB inventory missing ${expected}`);
  }
  if (!topologyBefore) fail('USB topology hash is missing');

  const browser = await chromium.launch({ headless: true, executablePath: CHROMIUM });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: BASE_URL });
  const page = await context.newPage();
  const csrfToken = await login(context, password);
  await page.goto('/api/health', { waitUntil: 'domcontentloaded' });

  let uploaded = false;
  let mounted = false;
  try {
    const mode = await api(context, csrfToken, '/api/hid/mode');
    const wakeup = await api(context, csrfToken, '/api/hid/usb-wakeup');
    const shortcuts = await api(context, csrfToken, '/api/hid/shortcuts');
    const mountedBefore = await api(context, csrfToken, '/api/storage/image/mounted');
    const cdromBefore = await api(context, csrfToken, '/api/storage/cdrom');
    const imagesBefore = await api(context, csrfToken, '/api/storage/image');
    let removedMountedStale = '';
    if (mountedBefore?.file) {
      const staleName = path.posix.basename(mountedBefore.file);
      if (!staleName.startsWith('hardened-usb-safe-') || !staleName.endsWith('.img')) {
        fail(`refusing to replace mounted user media: ${mountedBefore.file}`);
      }
      await ejectWithExplicitReconnect(context, csrfToken, 'stale_test_media_cleanup');
      await api(context, csrfToken, '/api/storage/image/delete', 'POST', { file: staleName });
      removedMountedStale = staleName;
      step(`removed_stale_test_media=${staleName}`);
    }
    if (cdromBefore?.cdrom !== 0) fail('refusing mass-storage test while CD-ROM mode is active');
    step(`hid_mode=${mode?.mode ?? 'unknown'}`);
    step(`usb_wakeup=${String(wakeup?.enabled)}`);
    step(`shortcut_count=${Array.isArray(shortcuts?.shortcuts) ? shortcuts.shortcuts.length : -1}`);
    step(`image_count_before=${Array.isArray(imagesBefore?.files) ? imagesBefore.files.length : -1}`);
    for (const stalePath of imagesBefore?.files || []) {
      const staleName = path.posix.basename(stalePath);
      if (staleName.startsWith('hardened-usb-safe-') && staleName.endsWith('.img')) {
        if (staleName === removedMountedStale) continue;
        await api(context, csrfToken, '/api/storage/image/delete', 'POST', { file: staleName });
        step(`removed_stale_test_media=${staleName}`);
      }
    }

    const hidBefore = await sendZeroHidReports(page);
    if (!hidBefore.opened) fail('HID websocket did not open');
    step(`hid_zero_reports_before_mount=ok`);
    step(`hid_ws_status_messages_before=${hidBefore.messages}`);

    await uploadImage(context, csrfToken);
    uploaded = true;
    const imagesUploaded = await api(context, csrfToken, '/api/storage/image');
    if (!imagesUploaded?.files?.includes(remoteImagePath)) fail('uploaded test image is not listed');
    step('virtual_media_upload=ok');

    await api(context, csrfToken, '/api/storage/image/mount', 'POST', { file: imageName, cdrom: false });
    mounted = true;
    const mountedState = await api(context, csrfToken, '/api/storage/image/mounted');
    const cdromMounted = await api(context, csrfToken, '/api/storage/cdrom');
    if (mountedState?.file !== remoteImagePath) fail(`unexpected mounted path: ${mountedState?.file}`);
    if (cdromMounted?.cdrom !== 0) fail('mass-storage image unexpectedly mounted as CD-ROM');
    step('virtual_media_mount=ok');

    const hidMounted = await sendZeroHidReports(page);
    if (!hidMounted.opened) fail('HID websocket did not reopen while media was mounted');
    step('hid_zero_reports_while_mounted=ok');

    try {
      await api(context, csrfToken, '/api/storage/image/mount', 'POST', { file: '', cdrom: false });
    } catch (error) {
      if (!String(error.message).includes('virtual media is busy')) throw error;
      step('virtual_media_eject_busy=yes');
      await ejectWithExplicitReconnect(context, csrfToken, 'virtual_media_eject');
    }
    mounted = false;
    const mountedAfterEject = await api(context, csrfToken, '/api/storage/image/mounted');
    if (mountedAfterEject?.file) fail('test image remained mounted after eject');
    step('virtual_media_eject=ok');

    await api(context, csrfToken, '/api/storage/image/delete', 'POST', { file: imageName });
    uploaded = false;
    const imagesAfter = await api(context, csrfToken, '/api/storage/image');
    if (imagesAfter?.files?.includes(remoteImagePath)) fail('test image remained after delete');
    step('virtual_media_delete=ok');

    const hidAfter = await sendZeroHidReports(page);
    if (!hidAfter.opened) fail('HID websocket did not reopen after media eject');
    step('hid_zero_reports_after_eject=ok');
  } finally {
    if (mounted || uploaded) {
      try {
        await api(context, csrfToken, '/api/storage/image/mount', 'POST', { file: '', cdrom: false });
      } catch {
        try { await ejectWithExplicitReconnect(context, csrfToken, 'finally_cleanup'); } catch {}
      }
    }
    if (uploaded) {
      try { await api(context, csrfToken, '/api/storage/image/delete', 'POST', { file: imageName }); } catch {}
    }
    await context.close();
    await browser.close();
  }

  const afterInventory = await ssh(password, `${inventoryCommand}
printf 'NEW_SERVER_ERRORS_BEGIN\\n'
sed -n '${logLines + 1},$p' /run/nanokvm-native.log 2>/dev/null | grep -E 'HID write failed|failed to recover HID|USB gadget did not reach|kernel oops' || true
printf 'NEW_SERVER_ERRORS_END\\n'
`);
  fs.writeFileSync(path.join(resultDir, 'after.txt'), afterInventory, { mode: 0o600 });
  const topologyAfter = afterInventory.match(/^TOPOLOGY_SHA=([0-9a-f]{64})$/m)?.[1] || '';
  if (topologyAfter !== topologyBefore) fail('USB configfs topology changed during safe test');
  for (const expected of [
    'UDC_STATE=configured', 'HIDG0=char:', 'HIDG1=char:', 'HIDG2=char:',
    'LUN_FILE=/dev/mmcblk0p3', 'LUN_CDROM=0', 'DMESG_ALERTS=0',
    'NEW_SERVER_ERRORS_BEGIN\nNEW_SERVER_ERRORS_END',
  ]) {
    if (!afterInventory.includes(expected)) fail(`USB postflight missing ${expected}`);
  }
  step(`topology_sha=${topologyAfter}`);
  step('SUCCESS: safe HID zero-report and mass-storage upload/mount/eject/delete tests passed');
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
