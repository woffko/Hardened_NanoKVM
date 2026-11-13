#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const CryptoJS = require('../web/node_modules/crypto-js');
const { request } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const EXPECTED_SYSTEM = '0.3.0-raw.6';
const EXPECTED_KERNEL = '5.10.4-tag-';
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const ARTIFACT_DIR = path.join(ROOT, 'build/latestbuildroot/sophgo-media-modules-5.10.4-v2/artifacts');
const S30ETH = path.join(ROOT, 'kvmapp/system/init.d/S30eth');
const POSTFLIGHT = path.join(ROOT, 'scripts/verify-latest-buildroot-device.cjs');
const STREAM_SOAK = path.join(ROOT, 'scripts/soak-latest-buildroot-streams.cjs');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `source-media-trial-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');
const knownHostsPath = path.join(resultDir, 'known_hosts');
const rollbackScriptPath = path.join(resultDir, 'S00akerneltrial');
const REMOTE_UPLOAD = '/tmp/hardened-source-media-trial-v1';
const REMOTE_BACKUP = '/mnt/system/ko/.hardened-source-media-trial-v1';
const REMOTE_STATE = '/etc/hardened-source-media-trial-v1';
const REMOTE_ROLLBACK = '/etc/init.d/S00akerneltrial';

function step(message) {
  fs.appendFileSync(reportPath, `${new Date().toISOString()} ${message}\n`, { mode: 0o600 });
}

function fail(message) {
  throw new Error(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sha256(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
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

async function run(command, args, input = undefined, secret = undefined, acceptedCodes = [0]) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: ROOT,
      env: {
        HOME: '/home/w0w',
        USER: 'w0w',
        LANG: 'C',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      },
      stdio: secret === undefined ? ['pipe', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      if (!acceptedCodes.includes(code)) {
        const error = new Error(`${path.basename(command)} failed with exit code ${code}`);
        error.exitCode = code;
        error.stderrBytes = Buffer.concat(stderr).length;
        reject(error);
      } else {
        resolve(Buffer.concat(stdout));
      }
    });
    if (secret !== undefined) {
      child.stdio[3].on('error', () => {});
      child.stdio[3].end(secret);
    }
    if (input !== undefined && child.stdin) {
      child.stdin.on('error', () => {});
      child.stdin.end(input);
    }
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
  step(`ssh_ed25519=${EXPECTED_ED25519}`);
}

function sshArgs(command) {
  return [
    '-d', '3', 'ssh',
    '-o', 'ConnectTimeout=10',
    '-o', 'ConnectionAttempts=1',
    '-o', 'PreferredAuthentications=password,keyboard-interactive',
    '-o', 'PubkeyAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    `root@${TARGET_IP}`,
    command,
  ];
}

async function ssh(password, command, acceptedCodes = [0]) {
  const output = await run(
    SSHPASS,
    sshArgs(command),
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
    acceptedCodes,
  );
  return output.toString('utf8');
}

async function scp(password, source, remoteName) {
  await run(
    SSHPASS,
    [
      '-d', '3', 'scp', '-q',
      '-o', 'ConnectTimeout=10',
      '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no',
      '-o', 'StrictHostKeyChecking=yes',
      '-o', `UserKnownHostsFile=${knownHostsPath}`,
      source,
      `root@${TARGET_IP}:${REMOTE_UPLOAD}/${remoteName}`,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
}

async function waitForNewBoot(password, previousBootId, label) {
  for (let attempt = 0; attempt < 180; attempt += 1) {
    try {
      const state = await ssh(password, 'cat /proc/sys/kernel/random/boot_id');
      const bootId = state.trim();
      if (bootId && bootId !== previousBootId) {
        step(`${label}_boot_id=${bootId}`);
        return bootId;
      }
    } catch {}
    await sleep(5000);
  }
  fail(`${label}: device did not return with a new boot id`);
}

async function waitForRuntime(password, bootId, label) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const state = await ssh(password, `set -eu
test "$(cat /proc/sys/kernel/random/boot_id)" = ${bootId}
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
test -n "$BACKEND_PID"
kill -0 "$BACKEND_PID"
grep -q '^soph_vcodec ' /proc/modules
grep -q '^soph_jpeg ' /proc/modules
grep -q '^soph_vc_driver ' /proc/modules
printf 'READY=yes\n'
`);
      if (state.includes('READY=yes')) {
        step(`${label}_runtime_ready=yes`);
        return;
      }
    } catch {}
    await sleep(2000);
  }
  fail(`${label}: runtime did not become ready`);
}

function encryptPassword(password) {
  return encodeURIComponent(CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString());
}

async function requestApiReboot(password, label) {
  const context = await request.newContext({
    baseURL: `https://${TARGET_IP}`,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Accept: 'application/json' },
    timeout: 30000,
  });
  try {
    const loginResponse = await context.post('/api/auth/login', {
      data: { username: 'admin', password: encryptPassword(password) },
    });
    const loginJson = await loginResponse.json();
    if (!loginResponse.ok() || loginJson?.code !== 0 || !loginJson?.data?.csrfToken) {
      fail(`${label}: API login failed`);
    }
    try {
      const response = await context.post('/api/vm/system/reboot', {
        headers: { 'x-csrf-token': loginJson.data.csrfToken },
        data: {},
        timeout: 30000,
      });
      if (response.ok()) {
        const json = await response.json();
        if (json?.code !== 0) fail(`${label}: reboot API returned code ${json?.code}`);
      }
    } catch (error) {
      step(`${label}_api_disconnect=${error.name}`);
    }
  } finally {
    await context.dispose();
  }
}

async function reboot(password, bootId, label) {
  step(`${label}_reboot_requested=yes`);
  await requestApiReboot(password, label);
  return waitForNewBoot(password, bootId, label);
}

async function runSecretChild(script, password) {
  await run(
    '/usr/bin/node',
    [script, '--confirm-device', TARGET_IP],
    Buffer.from(`${password}\n`, 'utf8'),
  );
}

function writeRollbackScript() {
  const content = `#!/bin/sh
set -eu
MODULE_DIR=/mnt/system/ko
BACKUP=${REMOTE_BACKUP}
STATE=${REMOTE_STATE}
LOG=/etc/hardened-source-media-trial.log

[ "\${1:-}" = "start" ] || exit 0
[ -f "$STATE/armed" ] || exit 0
BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
if [ ! -f "$STATE/attempted" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') first trial boot_id=$BOOT_ID pid=$$ ppid=$PPID args=$*" >> "$LOG"
    touch "$STATE/attempted"
    sync
    exit 0
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') automatic rollback boot_id=$BOOT_ID pid=$$ ppid=$PPID args=$*" >> "$LOG"
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
    cp -p "$BACKUP/$module" "$MODULE_DIR/$module"
done
cp -p "$BACKUP/S30eth.etc" /etc/init.d/S30eth
cp -p "$BACKUP/S30eth.kvmapp" /kvmapp/system/init.d/S30eth
rm -f "$STATE/armed" "$STATE/attempted"
touch "$STATE/rolled-back"
rm -f ${REMOTE_ROLLBACK}
sync
exit 0
`;
  fs.writeFileSync(rollbackScriptPath, content, { mode: 0o700 });
}

async function emergencyRollback(password) {
  const command = `set -eu
if [ -d ${REMOTE_BACKUP} ]; then
  for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
    [ -f ${REMOTE_BACKUP}/$module ] && cp -p ${REMOTE_BACKUP}/$module /mnt/system/ko/$module
  done
  [ -f ${REMOTE_BACKUP}/S30eth.etc ] && cp -p ${REMOTE_BACKUP}/S30eth.etc /etc/init.d/S30eth
  [ -f ${REMOTE_BACKUP}/S30eth.kvmapp ] && cp -p ${REMOTE_BACKUP}/S30eth.kvmapp /kvmapp/system/init.d/S30eth
fi
rm -f ${REMOTE_STATE}/armed ${REMOTE_STATE}/attempted ${REMOTE_ROLLBACK}
touch ${REMOTE_STATE}/emergency-rollback 2>/dev/null || true
sync
cat /proc/sys/kernel/random/boot_id
`;
  const output = await ssh(password, command);
  const bootId = output.trim().split(/\r?\n/).at(-1);
  step('emergency_rollback_staged=yes');
  const newBootId = await reboot(password, bootId, 'emergency_rollback');
  await waitForRuntime(password, newBootId, 'emergency_rollback');
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing module trial without --confirm-device ${TARGET_IP}`);
  }

  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  const inspectStateOnly = process.argv.includes('--inspect-state');
  const cleanupStateOnly = process.argv.includes('--cleanup-state');
  const forceRollback = process.argv.includes('--force-rollback');
  const trialSetIndex = process.argv.indexOf('--trial-set');
  const trialSet = trialSetIndex >= 0 ? process.argv[trialSetIndex + 1] : 'trio';
  const trialSets = new Map([
    ['control', []],
    ['vcodec', ['soph_vcodec.ko']],
    ['jpeg', ['soph_jpeg.ko']],
    ['vcodec-jpeg', ['soph_vcodec.ko', 'soph_jpeg.ko']],
    ['trio', ['soph_vcodec.ko', 'soph_jpeg.ko', 'soph_vc_driver.ko']],
  ]);
  if (!trialSets.has(trialSet)) fail(`unsupported trial set: ${trialSet}`);
  const trialModules = trialSets.get(trialSet);
  const vcodecArtifactIndex = process.argv.indexOf('--vcodec-artifact');
  if (vcodecArtifactIndex >= 0 && !process.argv[vcodecArtifactIndex + 1]) {
    fail('--vcodec-artifact requires a path');
  }
  const vcodecArtifact = vcodecArtifactIndex >= 0
    ? path.resolve(ROOT, process.argv[vcodecArtifactIndex + 1])
    : path.join(ARTIFACT_DIR, 'soph_vcodec.ko');
  const vcArtifactIndex = process.argv.indexOf('--vc-artifact');
  if (vcArtifactIndex >= 0 && !process.argv[vcArtifactIndex + 1]) {
    fail('--vc-artifact requires a path');
  }
  const vcArtifact = vcArtifactIndex >= 0
    ? path.resolve(ROOT, process.argv[vcArtifactIndex + 1])
    : path.join(ARTIFACT_DIR, 'soph_vc_driver.ko');
  const expectRcHierarchy = !process.argv.includes('--no-rc-hierarchy');

  const artifacts = new Map([
    ['soph_vcodec.ko', vcodecArtifact],
    ['soph_jpeg.ko', path.join(ARTIFACT_DIR, 'soph_jpeg.ko')],
    ['soph_vc_driver.ko', vcArtifact],
  ]);
  for (const filename of [SSHPASS, S30ETH, POSTFLIGHT, STREAM_SOAK, ...artifacts.values()]) {
    if (!fs.existsSync(filename)) fail(`required local file is missing: ${filename}`);
  }

  const newHashes = new Map();
  for (const [name, filename] of artifacts) newHashes.set(name, sha256(filename));
  const s30ethHash = sha256(S30ETH);
  step(`new_soph_vcodec_sha=${newHashes.get('soph_vcodec.ko')}`);
  step(`vcodec_artifact=${vcodecArtifact}`);
  step(`new_soph_jpeg_sha=${newHashes.get('soph_jpeg.ko')}`);
  step(`new_soph_vc_driver_sha=${newHashes.get('soph_vc_driver.ko')}`);
  step(`vc_artifact=${vcArtifact}`);
  step(`expect_rc_hierarchy=${expectRcHierarchy ? 'yes' : 'no'}`);
  step(`new_s30eth_sha=${s30ethHash}`);

  await prepareKnownHosts();

  if (inspectStateOnly) {
    const inspectText = await ssh(password, `set -eu
printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
printf 'UPTIME=%s\n' "$(cut -d' ' -f1 /proc/uptime)"
printf 'ARMED=%s\n' "$([ -f ${REMOTE_STATE}/armed ] && echo yes || echo no)"
printf 'ATTEMPTED=%s\n' "$([ -f ${REMOTE_STATE}/attempted ] && echo yes || echo no)"
printf 'ROLLED_BACK=%s\n' "$([ -f ${REMOTE_STATE}/rolled-back ] && echo yes || echo no)"
printf 'ROLLBACK_SCRIPT=%s\n' "$([ -f ${REMOTE_ROLLBACK} ] && echo present || echo absent)"
printf 'BACKUP=%s\n' "$([ -d ${REMOTE_BACKUP} ] && echo present || echo absent)"
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
  printf '%s_SHA=%s\n' "$(echo "$module" | tr '[:lower:].' '[:upper:]_')" "$(sha256sum /mnt/system/ko/$module | awk '{print $1}')"
done
printf 'S30ETH_SHA=%s\n' "$(sha256sum /etc/init.d/S30eth | awk '{print $1}')"
printf 'KVMAPP_S30ETH_SHA=%s\n' "$(sha256sum /kvmapp/system/init.d/S30eth | awk '{print $1}')"
printf 'MODULES=%s\n' "$(awk '$1 ~ /^soph_(vcodec|jpeg|vc_driver)$/ { print $1 }' /proc/modules | sort | tr '\n' ',' | sed 's/,$//')"
printf 'JPEG_SRCVERSION=%s\n' "$(cat /sys/module/soph_jpeg/srcversion 2>/dev/null || true)"
printf 'DNS_TOTAL=%s\n' "$(awk '$1 == "nameserver" { count++ } END { print count + 0 }' /etc/resolv.conf)"
printf 'DNS_UNIQUE=%s\n' "$(awk '$1 == "nameserver" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
printf 'BACKEND=%s\n' "$([ -s /tmp/nanokvm-server.pid ] && kill -0 "$(cat /tmp/nanokvm-server.pid)" 2>/dev/null && echo running || echo stopped)"
printf 'DMESG_ALERTS=%s\n' "$(dmesg | grep -Eic 'oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format' || true)"
printf 'TRIAL_LOG_BEGIN\n'
cat /etc/hardened-source-media-trial.log 2>/dev/null || true
printf 'TRIAL_LOG_END\n'
printf 'DMESG_MEDIA_BEGIN\n'
dmesg | grep -Ei 'soph|vcodec|jpeg|vc_driver|Unknown symbol|invalid module|oops|panic|BUG:' | tail -n 200 || true
printf 'DMESG_MEDIA_END\n'
`);
    fs.writeFileSync(path.join(resultDir, 'inspect-state.txt'), inspectText, { mode: 0o600 });
    step('SUCCESS: trial state inspected without mutation');
    return;
  }

  if (cleanupStateOnly) {
    await ssh(password, `set -eu
test ! -f ${REMOTE_STATE}/armed
test ! -f ${REMOTE_STATE}/attempted
test -f ${REMOTE_STATE}/rolled-back || test -f ${REMOTE_STATE}/emergency-rollback
test ! -f ${REMOTE_ROLLBACK}
test -d ${REMOTE_BACKUP}
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
  cmp -s ${REMOTE_BACKUP}/$module /mnt/system/ko/$module
done
if [ -f ${REMOTE_BACKUP}/S30eth.etc ]; then
  cmp -s ${REMOTE_BACKUP}/S30eth.etc /etc/init.d/S30eth
else
  cmp -s ${REMOTE_BACKUP}/S30eth /etc/init.d/S30eth
fi
if [ -f ${REMOTE_BACKUP}/S30eth.kvmapp ]; then
  cmp -s ${REMOTE_BACKUP}/S30eth.kvmapp /kvmapp/system/init.d/S30eth
fi
rm -rf ${REMOTE_UPLOAD} ${REMOTE_BACKUP} ${REMOTE_STATE}
sync
`);
    step('SUCCESS: completed rollback state cleaned after byte comparison');
    return;
  }

  if (forceRollback) {
    const diagnostic = await ssh(password, `
printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
printf 'ARMED=%s\n' "$([ -f ${REMOTE_STATE}/armed ] && echo yes || echo no)"
printf 'ATTEMPTED=%s\n' "$([ -f ${REMOTE_STATE}/attempted ] && echo yes || echo no)"
printf 'SCREEN_TYPE=%s\n' "$(cat /kvmapp/kvm/type 2>/dev/null || true)"
printf 'SCREEN_STATE=%s\n' "$(cat /kvmapp/kvm/state 2>/dev/null || true)"
printf 'DMESG_ALERTS=%s\n' "$(dmesg | grep -Eic 'oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format' || true)"
printf 'SERVER_LOG_BEGIN\n'
tail -n 160 /run/nanokvm-native.log 2>/dev/null || true
printf 'SERVER_LOG_END\n'
printf 'KVM_SYSTEM_LOG_BEGIN\n'
tail -n 160 /tmp/kvm_system.log 2>/dev/null || true
printf 'KVM_SYSTEM_LOG_END\n'
printf 'DMESG_MEDIA_BEGIN\n'
dmesg | grep -Ei 'soph|vcodec|jpeg|vc_driver|venc|h264|Unknown symbol|invalid module|oops|panic|BUG:' | tail -n 240 || true
printf 'DMESG_MEDIA_END\n'
`);
    fs.writeFileSync(path.join(resultDir, 'force-rollback-diagnostic.txt'), diagnostic, { mode: 0o600 });
    const state = parseFields(diagnostic);
    if (state.get('ARMED') !== 'yes' || state.get('ATTEMPTED') !== 'yes') {
      fail('refusing forced rollback without an armed attempted trial');
    }
    await emergencyRollback(password);
    step('SUCCESS: diagnostic captured and emergency rollback completed');
    return;
  }

  writeRollbackScript();

  let staged = false;
  let trialBootId = '';
  try {
    const preflightText = await ssh(password, `set -eu
test "$(cat /etc/kvm/system-version.json | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' | head -n 1)" = ${EXPECTED_SYSTEM}
test "$(uname -r)" = ${EXPECTED_KERNEL}
test ! -e ${REMOTE_BACKUP}
test ! -e ${REMOTE_STATE}
test ! -e ${REMOTE_ROLLBACK}
printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
printf 'SYSTEM=%s\n' "${EXPECTED_SYSTEM}"
printf 'KERNEL=%s\n' "$(uname -r)"
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
  printf 'OLD_%s_SHA=%s\n' "$(echo "$module" | tr '[:lower:].' '[:upper:]_')" "$(sha256sum /mnt/system/ko/$module | awk '{print $1}')"
done
printf 'OLD_S30ETH_SHA=%s\n' "$(sha256sum /etc/init.d/S30eth | awk '{print $1}')"
printf 'OLD_KVMAPP_S30ETH_SHA=%s\n' "$(sha256sum /kvmapp/system/init.d/S30eth | awk '{print $1}')"
printf 'DNS_TOTAL=%s\n' "$(awk '$1 == "nameserver" { count++ } END { print count + 0 }' /etc/resolv.conf)"
printf 'DNS_UNIQUE=%s\n' "$(awk '$1 == "nameserver" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
`);
    fs.writeFileSync(path.join(resultDir, 'preflight.txt'), preflightText, { mode: 0o600 });
    const preflight = parseFields(preflightText);
    const initialBootId = preflight.get('BOOT_ID');
    if (!initialBootId) fail('preflight boot id is missing');
    step(`preflight_dns_total=${preflight.get('DNS_TOTAL')}`);
    step(`preflight_dns_unique=${preflight.get('DNS_UNIQUE')}`);
    step(`trial_set=${trialSet}`);

    await ssh(password, `set -eu; mkdir -p ${REMOTE_UPLOAD}; chmod 0700 ${REMOTE_UPLOAD}`);
    for (const [name, filename] of artifacts) await scp(password, filename, name);
    await scp(password, S30ETH, 'S30eth');
    await scp(password, rollbackScriptPath, 'S00akerneltrial');

    const stageCommand = `set -eu
mkdir -p ${REMOTE_BACKUP} ${REMOTE_STATE}
chmod 0700 ${REMOTE_BACKUP} ${REMOTE_STATE}
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
  cp -p /mnt/system/ko/$module ${REMOTE_BACKUP}/$module
done
cp -p /etc/init.d/S30eth ${REMOTE_BACKUP}/S30eth.etc
cp -p /kvmapp/system/init.d/S30eth ${REMOTE_BACKUP}/S30eth.kvmapp
test "$(sha256sum ${REMOTE_UPLOAD}/soph_vcodec.ko | awk '{print $1}')" = ${newHashes.get('soph_vcodec.ko')}
test "$(sha256sum ${REMOTE_UPLOAD}/soph_jpeg.ko | awk '{print $1}')" = ${newHashes.get('soph_jpeg.ko')}
test "$(sha256sum ${REMOTE_UPLOAD}/soph_vc_driver.ko | awk '{print $1}')" = ${newHashes.get('soph_vc_driver.ko')}
test "$(sha256sum ${REMOTE_UPLOAD}/S30eth | awk '{print $1}')" = ${s30ethHash}
for module in ${trialModules.join(' ')}; do
  cp ${REMOTE_UPLOAD}/$module /mnt/system/ko/$module.new
  chmod 0644 /mnt/system/ko/$module.new
  mv /mnt/system/ko/$module.new /mnt/system/ko/$module
done
cp ${REMOTE_UPLOAD}/S30eth /etc/init.d/S30eth.new
chmod 0755 /etc/init.d/S30eth.new
mv /etc/init.d/S30eth.new /etc/init.d/S30eth
cp ${REMOTE_UPLOAD}/S30eth /kvmapp/system/init.d/S30eth.new
chmod 0755 /kvmapp/system/init.d/S30eth.new
mv /kvmapp/system/init.d/S30eth.new /kvmapp/system/init.d/S30eth
cp ${REMOTE_UPLOAD}/S00akerneltrial ${REMOTE_ROLLBACK}.new
chmod 0755 ${REMOTE_ROLLBACK}.new
mv ${REMOTE_ROLLBACK}.new ${REMOTE_ROLLBACK}
touch ${REMOTE_STATE}/armed
rm -f ${REMOTE_STATE}/attempted ${REMOTE_STATE}/rolled-back
sync
printf 'STAGED=yes\n'
printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
`;
    const stagedText = await ssh(password, stageCommand);
    if (!stagedText.includes('STAGED=yes')) fail('remote staging did not complete');
    staged = true;
    step('source_media_staged=yes');

    trialBootId = await reboot(password, initialBootId, 'trial');
    await waitForRuntime(password, trialBootId, 'trial');
    const expectedTrialHashes = new Map([...artifacts.keys()].map((module) => {
      const key = `OLD_${module.toUpperCase().replaceAll('.', '_')}_SHA`;
      const expected = trialModules.includes(module) ? newHashes.get(module) : preflight.get(key);
      if (!expected) fail(`missing expected hash for ${module}`);
      return [module, expected];
    }));
    const trialText = await ssh(password, `
DNS_TOTAL="$(awk '$1 == "nameserver" { count++ } END { print count + 0 }' /etc/resolv.conf)"
DNS_UNIQUE="$(awk '$1 == "nameserver" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
printf 'ARMED=%s\n' "$([ -f ${REMOTE_STATE}/armed ] && echo yes || echo no)"
printf 'ATTEMPTED=%s\n' "$([ -f ${REMOTE_STATE}/attempted ] && echo yes || echo no)"
printf 'SOPH_VCODEC_KO_SHA=%s\n' "$(sha256sum /mnt/system/ko/soph_vcodec.ko | awk '{print $1}')"
printf 'SOPH_JPEG_KO_SHA=%s\n' "$(sha256sum /mnt/system/ko/soph_jpeg.ko | awk '{print $1}')"
printf 'SOPH_VC_DRIVER_KO_SHA=%s\n' "$(sha256sum /mnt/system/ko/soph_vc_driver.ko | awk '{print $1}')"
printf 'S30ETH_SHA=%s\n' "$(sha256sum /etc/init.d/S30eth | awk '{print $1}')"
printf 'KVMAPP_S30ETH_SHA=%s\n' "$(sha256sum /kvmapp/system/init.d/S30eth | awk '{print $1}')"
printf 'MODULE_VCODEC=%s\n' "$(grep -q '^soph_vcodec ' /proc/modules && echo loaded || echo missing)"
printf 'MODULE_JPEG=%s\n' "$(grep -q '^soph_jpeg ' /proc/modules && echo loaded || echo missing)"
printf 'MODULE_VC_DRIVER=%s\n' "$(grep -q '^soph_vc_driver ' /proc/modules && echo loaded || echo missing)"
printf 'VCODEC_LOCK_SYMBOL=%s\n' "$(awk '$3 == "vcodec_lock" && $4 == "[soph_vcodec]" { found=1 } END { print found ? "present" : "absent" }' /proc/kallsyms)"
printf 'RC_HIERARCHY=%s\n' "$([ -e /sys/module/soph_vc_driver/parameters/rcHierarchy ] && echo present || echo absent)"
printf 'JPEG_SRCVERSION=%s\n' "$(cat /sys/module/soph_jpeg/srcversion 2>/dev/null || true)"
printf 'MAX_VENC=%s\n' "$(cat /sys/module/soph_vc_driver/parameters/MaxVencChnNum 2>/dev/null || true)"
printf 'MAX_VDEC=%s\n' "$(cat /sys/module/soph_vc_driver/parameters/MaxVdecChnNum 2>/dev/null || true)"
BACKEND_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
printf 'BACKEND=%s\n' "$([ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null && echo running || echo stopped)"
printf 'DNS_TOTAL=%s\n' "$DNS_TOTAL"
printf 'DNS_UNIQUE=%s\n' "$DNS_UNIQUE"
printf 'DMESG_ALERTS=%s\n' "$(dmesg | grep -Eic 'oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format' || true)"
printf 'DMESG_MEDIA_BEGIN\n'
dmesg | grep -Ei 'soph|vcodec|jpeg|vc_driver|Unknown symbol|invalid module|oops|panic|BUG:' | tail -n 160 || true
printf 'DMESG_MEDIA_END\n'
`);
    fs.writeFileSync(path.join(resultDir, 'trial-postboot.txt'), trialText, { mode: 0o600 });
    const trial = parseFields(trialText);
    const trialFailures = [];
    const requireTrial = (field, expected) => {
      if (trial.get(field) !== expected) trialFailures.push(`${field}=${trial.get(field) ?? 'missing'}`);
    };
    requireTrial('BOOT_ID', trialBootId);
    requireTrial('ARMED', 'yes');
    requireTrial('ATTEMPTED', 'yes');
    requireTrial('SOPH_VCODEC_KO_SHA', expectedTrialHashes.get('soph_vcodec.ko'));
    requireTrial('SOPH_JPEG_KO_SHA', expectedTrialHashes.get('soph_jpeg.ko'));
    requireTrial('SOPH_VC_DRIVER_KO_SHA', expectedTrialHashes.get('soph_vc_driver.ko'));
    requireTrial('S30ETH_SHA', s30ethHash);
    requireTrial('KVMAPP_S30ETH_SHA', s30ethHash);
    requireTrial('MODULE_VCODEC', 'loaded');
    requireTrial('MODULE_JPEG', 'loaded');
    requireTrial('MODULE_VC_DRIVER', 'loaded');
    requireTrial('JPEG_SRCVERSION', '625882D05A26BB4B2FD9A6E');
    requireTrial('MAX_VENC', '9');
    requireTrial('MAX_VDEC', '9');
    requireTrial('BACKEND', 'running');
    requireTrial('DMESG_ALERTS', '0');
    if (trialModules.includes('soph_vcodec.ko')) requireTrial('VCODEC_LOCK_SYMBOL', 'present');
    if (trialModules.includes('soph_vc_driver.ko')) {
      requireTrial('RC_HIERARCHY', expectRcHierarchy ? 'present' : 'absent');
    }
    if (trial.get('DNS_TOTAL') !== trial.get('DNS_UNIQUE')) {
      trialFailures.push(`DNS=${trial.get('DNS_TOTAL')}/${trial.get('DNS_UNIQUE')}`);
    }
    if (trialFailures.length) {
      fail(`source-built media module postboot validation failed: ${trialFailures.join(',')}`);
    }
    step(`trial_dns_total=${trial.get('DNS_TOTAL')}`);
    step(`trial_dns_unique=${trial.get('DNS_UNIQUE')}`);
    step('trial_modules_loaded=yes');
    step('trial_dmesg_alerts=0');

    await runSecretChild(POSTFLIGHT, password);
    step('trial_core_postflight=passed');
    await runSecretChild(STREAM_SOAK, password);
    step('trial_stream_soak=passed');

    const restoreText = await ssh(password, `set -eu
for module in soph_vcodec.ko soph_jpeg.ko soph_vc_driver.ko; do
  cp -p ${REMOTE_BACKUP}/$module /mnt/system/ko/$module
done
rm -f ${REMOTE_STATE}/armed ${REMOTE_STATE}/attempted ${REMOTE_ROLLBACK}
touch ${REMOTE_STATE}/trial-passed
sync
printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
`);
    const restoreBootId = parseFields(restoreText).get('BOOT_ID') || trialBootId;
    const finalBootId = await reboot(password, restoreBootId, 'restore');
    await waitForRuntime(password, finalBootId, 'restore');

    const finalText = await ssh(password, `set -eu
test "$(sha256sum /mnt/system/ko/soph_vcodec.ko | awk '{print $1}')" = ${preflight.get('OLD_SOPH_VCODEC_KO_SHA')}
test "$(sha256sum /mnt/system/ko/soph_jpeg.ko | awk '{print $1}')" = ${preflight.get('OLD_SOPH_JPEG_KO_SHA')}
test "$(sha256sum /mnt/system/ko/soph_vc_driver.ko | awk '{print $1}')" = ${preflight.get('OLD_SOPH_VC_DRIVER_KO_SHA')}
test "$(sha256sum /etc/init.d/S30eth | awk '{print $1}')" = ${s30ethHash}
test "$(sha256sum /kvmapp/system/init.d/S30eth | awk '{print $1}')" = ${s30ethHash}
grep -q '^soph_vcodec ' /proc/modules
grep -q '^soph_jpeg ' /proc/modules
grep -q '^soph_vc_driver ' /proc/modules
DNS_TOTAL="$(awk '$1 == "nameserver" { count++ } END { print count + 0 }' /etc/resolv.conf)"
DNS_UNIQUE="$(awk '$1 == "nameserver" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
test "$DNS_TOTAL" -eq "$DNS_UNIQUE"
printf 'BOOT_ID=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
printf 'DNS_TOTAL=%s\n' "$DNS_TOTAL"
printf 'DNS_UNIQUE=%s\n' "$DNS_UNIQUE"
printf 'DMESG_ALERTS=%s\n' "$(dmesg | grep -Eic 'oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format' || true)"
printf 'ORIGINAL_MODULES=restored\n'
`);
    fs.writeFileSync(path.join(resultDir, 'final-postboot.txt'), finalText, { mode: 0o600 });
    const final = parseFields(finalText);
    if (final.get('BOOT_ID') !== finalBootId || final.get('ORIGINAL_MODULES') !== 'restored' || final.get('DMESG_ALERTS') !== '0') {
      fail('final restored-module validation failed');
    }
    await runSecretChild(POSTFLIGHT, password);
    step('final_core_postflight=passed');
    await ssh(password, `rm -rf ${REMOTE_UPLOAD} ${REMOTE_BACKUP} ${REMOTE_STATE}; sync`);
    staged = false;
    step(`final_dns_total=${final.get('DNS_TOTAL')}`);
    step(`final_dns_unique=${final.get('DNS_UNIQUE')}`);
    step('original_modules_restored=yes');
    step('dns_hotfix_retained=yes');
    step(`SUCCESS: source-built media trial ${trialSet} passed and original modules restored`);
  } catch (error) {
    step(`FAILED: ${error.message}`);
    if (staged) {
      try {
        await emergencyRollback(password);
        step('emergency_rollback=completed');
      } catch (rollbackError) {
        step(`emergency_rollback=failed:${rollbackError.message}`);
        step('manual_power_cycle_will_trigger_early_boot_rollback=yes');
      }
    }
    throw error;
  }
}

main().catch((error) => {
  try { step(`TOP_LEVEL_FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
