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
const SOURCE_SYSTEM_VERSION = '0.3.0-raw.9';
const SYSTEM_VERSION = '0.3.0-raw.10';
const APP_VERSION = '2.0.40';
const APP_ARCHIVE_SHA256 = '22dacfdb7627f0914cae201e53d353d96d12b9aa7d01d8f4c4ff9f68c9857ba3';
const ARCHIVE_SHA256 = 'bc01de0bc47de1a07fd931a7a50ecfbaf2b0848fa5588b386990daae0ec0314a';
const BACKEND_SHA256 = 'bf6af66c99cfc5d1b526d41eb9400cc87a99160c9cbf7a6e1eedae32bb247192';
const BUILDROOT_BACKEND_SHA256 = '04e50160903434a1086ae337c3522ea93c1f2292e01833ca24db1de70882bdb4';
const KVM_SYSTEM_SHA256 = 'f919c1b6ec1bf175d4d32b72f5ff666729422af6b2e34d23f0aa37c5193d32ef';
const S30ETH_SHA256 = '55b94ccb2ae9d1143eb4028a08c72f66bcd59b693599b39b39498f69b4642b77';
const SOPH_VCODEC_SHA256 = '0f0927cd796275f2241e8914b3efa57b124b8cc2aabc087ee899a56346a5c2be';
const SOPH_JPEG_SHA256 = 'eacf2af2c75c23816af129843912f5072c9cb81d44434d563ceb449ee2899666';
const SOPH_VC_DRIVER_SHA256 = 'cc543c2a1b25c63c0372d7a687643605b1d07a5624403e3cf7d74b52ecadecf5';
const LIBKVM_SHA256 = '387f1c7f54fb67ecc0eafa961946eef7972022a92ad443fb68c3d88ef6d2f24f';
const LIBKVM_MMF_SHA256 = 'be269c595b454930abeb9bb05eb67ec708894eb2df1650c4d99ee1162e1e3f2d';
const REMOTE_SYSLOG_HOST = '10.0.77.177';
const REMOTE_SYSLOG_PORT = 514;
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const APP_ARCHIVE = path.join(ROOT, 'build/artifacts/nanokvm-kvmapp-rust.tar.gz');
const RAW_DIR = path.join(ROOT, 'build/latestbuildroot', `raw-system-update-${SYSTEM_VERSION}`, 'artifacts');
const RAW_ARCHIVE = path.join(RAW_DIR, `hardened-nanokvm-system-${SYSTEM_VERSION}.tar.gz`);
const METADATA = path.join(RAW_DIR, 'system-latest.json');
const SIGNATURE = `${METADATA}.sig`;
const PUBLIC_KEY = path.join(ROOT, 'kvmapp/system/keys/system-update-signing.pub.pem');
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const REMOTE_STAGE = '/data/.hardened-kvmcache/system-update';
const PRESERVE_ROOT = `${REMOTE_STAGE}/preserve/root`;
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `install-${SYSTEM_VERSION}-${TARGET_IP}-${runId}`);
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

async function runProcess(command, args, input = undefined, secretInput = undefined) {
  return new Promise((resolve, reject) => {
    const stdio = secretInput === undefined
      ? ['pipe', 'pipe', 'pipe']
      : [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe', 'pipe'];
    const child = spawn(command, args, {
      cwd: ROOT,
      env: {
        HOME: '/home/w0w',
        USER: 'w0w',
        LANG: 'C',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      },
      stdio,
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        const error = new Error(`${path.basename(command)} failed with exit code ${code}`);
        error.exitCode = code;
        error.stderrBytes = Buffer.concat(stderr).length;
        reject(error);
        return;
      }
      resolve(Buffer.concat(stdout));
    });
    if (secretInput !== undefined) child.stdio[3].end(secretInput);
    if (input !== undefined && child.stdin) child.stdin.end(input);
    else if (child.stdin) child.stdin.end();
  });
}

async function prepareKnownHosts() {
  const keys = await runProcess('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await runProcess('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    fail('current SSH fingerprint does not match the physically confirmed candidate');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });
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

async function ssh(password, command) {
  const output = await runProcess(
    SSHPASS,
    sshArgs(command),
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
  return output.toString('utf8');
}

async function scp(password, localPath, remotePath) {
  await runProcess(
    SSHPASS,
    [
      '-d', '3', 'scp', '-O',
      '-o', 'ConnectTimeout=10',
      '-o', 'ConnectionAttempts=1',
      '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no',
      '-o', 'StrictHostKeyChecking=yes',
      '-o', `UserKnownHostsFile=${knownHostsPath}`,
      localPath,
      `root@${TARGET_IP}:${remotePath}`,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
}

async function newApiContext(baseURL) {
  return request.newContext({
    baseURL,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Accept: 'application/json' },
    timeout: 60 * 60 * 1000,
  });
}

async function connectApiOnce() {
  for (const baseURL of [`https://${TARGET_IP}`, `http://${TARGET_IP}`]) {
    const context = await newApiContext(baseURL);
    try {
      const response = await context.get('/api/health', { timeout: 4000 });
      const json = await response.json();
      if (response.ok() && json?.code === 0 && json?.data?.status === 'ok') {
        return { context, baseURL };
      }
    } catch {}
    await context.dispose();
  }
  return null;
}

function encryptPassword(password) {
  return encodeURIComponent(
    CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString(),
  );
}

async function login(context, password) {
  const response = await context.post('/api/auth/login', {
    data: { username: 'admin', password: encryptPassword(password) },
    timeout: 30000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) {
    fail(`API login failed: code=${json?.code ?? 'unknown'} message=${json?.msg ?? response.status()}`);
  }
  return json.data.csrfToken;
}

async function api(context, csrfToken, pathname, method = 'GET', body = undefined) {
  const response = await context.fetch(pathname, {
    method,
    data: body,
    headers: method === 'GET' ? {} : { 'x-csrf-token': csrfToken },
    timeout: 60 * 60 * 1000,
  });
  const json = await response.json();
  return { status: response.status(), json };
}

function requireApiOk(result, operation, requireData = true) {
  if (result.status >= 400 || result.json?.code !== 0 || (requireData && !result.json?.data)) {
    fail(`${operation} failed: code=${result.json?.code ?? 'unknown'} message=${result.json?.msg ?? result.status}`);
  }
  return result.json.data;
}

async function waitForCycle(oldContext, label) {
  step(`${label}: waiting for service shutdown`);
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

  step(`${label}: waiting for HTTP or HTTPS service return`);
  for (let attempt = 0; attempt < 180; attempt += 1) {
    const connected = await connectApiOnce();
    if (connected) return connected;
    await sleep(5000);
  }
  fail(`${label}: device did not return within 15 minutes`);
}

async function waitBootGood(context, csrfToken) {
  for (let attempt = 0; attempt < 24; attempt += 1) {
    const status = requireApiOk(
      await api(context, csrfToken, '/api/system-update/status'),
      'system status',
    );
    if (!status.pending) return status;
    await sleep(5000);
  }
  fail('replacement raw was not auto-confirmed');
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing replacement install without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  step('validating local app and signed replacement inputs');
  for (const filename of [APP_ARCHIVE, RAW_ARCHIVE, METADATA, SIGNATURE, PUBLIC_KEY, SSHPASS]) {
    if (!fs.existsSync(filename)) fail(`missing input: ${filename}`);
  }
  if ((await hashFile(APP_ARCHIVE)) !== APP_ARCHIVE_SHA256) fail('application archive sha256 mismatch');
  if ((await hashFile(RAW_ARCHIVE)) !== ARCHIVE_SHA256) fail('replacement archive sha256 mismatch');
  await runProcess(path.join(ROOT, 'scripts/verify-system-update-metadata.sh'), [METADATA, SIGNATURE, PUBLIC_KEY]);
  const latest = JSON.parse(fs.readFileSync(METADATA, 'utf8'));
  if (latest.version !== SYSTEM_VERSION || latest.sha256 !== ARCHIVE_SHA256) fail('replacement metadata mismatch');
  const manifestRaw = await runProcess('/usr/bin/tar', ['-xOf', RAW_ARCHIVE, 'manifest.json']);
  const manifest = JSON.parse(manifestRaw.toString('utf8'));
  if (manifest.version !== SYSTEM_VERSION) fail('replacement manifest version mismatch');
  const stagedPath = path.join(resultDir, 'staged.json');
  fs.writeFileSync(stagedPath, `${JSON.stringify({
    staged_at: Math.floor(Date.now() / 1000),
    latest,
    manifest,
  }, null, 2)}\n`, { mode: 0o600 });

  await prepareKnownHosts();
  const firstConnection = await connectApiOnce();
  if (!firstConnection) fail('current API is unreachable');
  let { context, baseURL } = firstConnection;
  let csrfToken = await login(context, password);
  step(`before_api=${baseURL}`);

  const beforeVersion = requireApiOk(
    await api(context, csrfToken, '/api/system-update/version'),
    'current system version',
  ).current;
  if (beforeVersion.version !== SOURCE_SYSTEM_VERSION) {
    fail(`unexpected source system version: ${beforeVersion.version}`);
  }

  step('restoring preserved hostname and HTTPS sentinel before replacement');
  const restoreBefore = await ssh(password, `set -eu
test -s '${PRESERVE_ROOT}/etc/hostname'
test -s '${PRESERVE_ROOT}/etc/kvm/server.yaml'
cp -p '${PRESERVE_ROOT}/etc/hostname' /etc/hostname
cp -p '${PRESERVE_ROOT}/etc/kvm/server.yaml' /etc/kvm/server.yaml
hostname "$(head -n 1 /etc/hostname | tr -d '\\r\\n')"
chmod 0644 /etc/hostname /etc/kvm/server.yaml
printf 'HOSTNAME=%s\\n' "$(hostname)"
printf 'PROTO=%s\\n' "$(awk -F: '/^[[:space:]]*proto:/ { value=$2; gsub(/[[:space:]\"]/, "", value); print value; exit }' /etc/kvm/server.yaml)"
printf 'RESTORE_DONE_VALUE=%s\\n' "$(cat '${REMOTE_STAGE}/root-restore-done' 2>/dev/null || true)"
sync
`);
  fs.writeFileSync(path.join(resultDir, 'restore-sentinel-before.txt'), restoreBefore, { mode: 0o600 });
  if (!restoreBefore.includes('HOSTNAME=secondary') || !restoreBefore.includes('PROTO=https')) {
    fail('preserved hostname/HTTPS sentinel is invalid');
  }
  const oldRestoreValue = restoreBefore.match(/RESTORE_DONE_VALUE=([^\r\n]*)/)?.[1] || '';

  const updaterState = await ssh(password, `set -eu
printf 'BACKEND_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/NanoKVM-Server | awk '{print $1}')"
printf 'BACKEND_RUNTIME_SHA=%s\\n' "$(sha256sum /tmp/server/NanoKVM-Server | awk '{print $1}')"
printf 'S01_HOSTNAME_FIX=%s\\n' "$(grep -q apply_restored_runtime_state /kvmapp/system/init.d/S01fs && echo present || echo missing)"
printf 'CERT=%s\\n' "$([ -s /etc/kvm/server.crt ] && echo present || echo missing)"
printf 'KEY=%s\\n' "$([ -s /etc/kvm/server.key ] && echo present || echo missing)"
  `);
  fs.writeFileSync(path.join(resultDir, 'fixed-updater-state.txt'), updaterState, { mode: 0o600 });
  const backendDiskSha = updaterState.match(/^BACKEND_DISK_SHA=([0-9a-f]{64})$/m)?.[1] || '';
  const backendRuntimeSha = updaterState.match(/^BACKEND_RUNTIME_SHA=([0-9a-f]{64})$/m)?.[1] || '';
  const acceptedBackendHashes = [BACKEND_SHA256, BUILDROOT_BACKEND_SHA256];
  const fixedUpdaterReady = acceptedBackendHashes.includes(backendDiskSha)
    && backendRuntimeSha === backendDiskSha
    && [
    'S01_HOSTNAME_FIX=present',
    'CERT=present',
    'KEY=present',
    ].every((expected) => updaterState.includes(expected));

  if (fixedUpdaterReady) {
    step('fixed app updater already active; skipping duplicate offline app update');
  } else {
    step('installing fixed app updater through offline application API');
    const appUpload = await context.post('/api/application/update/offline', {
      headers: { 'x-csrf-token': csrfToken },
      multipart: {
        file: {
          name: `hardened-nanokvm-kvmapp-${APP_VERSION}-systemfix.tar.gz`,
          mimeType: 'application/gzip',
          buffer: fs.readFileSync(APP_ARCHIVE),
        },
      },
      timeout: 15 * 60 * 1000,
    });
    const appUploadJson = await appUpload.json();
    if (!appUpload.ok() || appUploadJson?.code !== 0) {
      fail(`offline app update failed: ${appUploadJson?.msg ?? appUpload.status()}`);
    }

    ({ context, baseURL } = await waitForCycle(context, 'app update'));
    csrfToken = await login(context, password);
    step(`after_app_update_api=${baseURL}`);
  }
  if (baseURL !== `https://${TARGET_IP}`) fail('restored HTTPS config was not applied after app restart');
  const deployedBackendHash = (await ssh(
    password,
    "sha256sum /kvmapp/server/NanoKVM-Server | awk '{print $1}'",
  )).trim();
  if (!acceptedBackendHashes.includes(deployedBackendHash)) {
    fail('fixed updater backend hash mismatch on device');
  }
  step(`fixed_backend_sha256=${deployedBackendHash}`);

  const syslogConfigBefore = requireApiOk(
    await api(context, csrfToken, '/api/system-log/config'),
    'remote syslog sentinel before raw update',
  ).config;
  if (
    syslogConfigBefore?.remoteEnabled !== true
    || syslogConfigBefore?.remoteHost !== REMOTE_SYSLOG_HOST
    || syslogConfigBefore?.remotePort !== REMOTE_SYSLOG_PORT
  ) {
    fail('remote syslog sentinel is not configured before raw update');
  }
  const syslogBefore = await ssh(password, `set -eu
printf 'CONFIG=%s\\n' "$(grep -Fq '${REMOTE_SYSLOG_HOST}' /etc/kvm/syslog.json && echo present || echo missing)"
printf 'SYSLOG_DEFAULT=%s\\n' "$(grep -Fq -- '-R ${REMOTE_SYSLOG_HOST}:${REMOTE_SYSLOG_PORT}' /etc/default/syslogd && grep -Fq -- '-L' /etc/default/syslogd && echo configured || echo missing)"
printf 'KLOG_DEFAULT=%s\\n' "$([ -s /etc/default/klogd ] && echo present || echo missing)"
SYSLOG_PID="$(cat /var/run/syslogd.pid 2>/dev/null || true)"
printf 'SYSLOG_RUNNING=%s\\n' "$([ -n "$SYSLOG_PID" ] && kill -0 "$SYSLOG_PID" 2>/dev/null && echo yes || echo no)"
printf 'SYSLOG_CMDLINE=%s\\n' "$(tr '\\0' ' ' < "/proc/$SYSLOG_PID/cmdline" 2>/dev/null || true)"
`);
  fs.writeFileSync(path.join(resultDir, 'remote-syslog-before.txt'), syslogBefore, { mode: 0o600 });
  for (const expected of [
    'CONFIG=present', 'SYSLOG_DEFAULT=configured', 'KLOG_DEFAULT=present',
    'SYSLOG_RUNNING=yes', `-R ${REMOTE_SYSLOG_HOST}:${REMOTE_SYSLOG_PORT}`, '-L',
  ]) {
    if (!syslogBefore.includes(expected)) fail(`remote syslog preflight missing ${expected}`);
  }
  step(`remote_syslog_sentinel=${REMOTE_SYSLOG_HOST}:${REMOTE_SYSLOG_PORT}/udp`);

  step(`uploading signed ${SYSTEM_VERSION} archive and staged record`);
  const remoteArchive = `${REMOTE_STAGE}/${path.basename(RAW_ARCHIVE)}`;
  await ssh(password, `set -eu
mkdir -p '${REMOTE_STAGE}'
rm -rf '${REMOTE_STAGE}/extract'
rm -f '${REMOTE_STAGE}/progress.json' '${REMOTE_STAGE}/staged.json'
rm -f '${remoteArchive}.incoming' '${REMOTE_STAGE}/staged.json.incoming'
`);
  await scp(password, RAW_ARCHIVE, `${remoteArchive}.incoming`);
  await scp(password, stagedPath, `${REMOTE_STAGE}/staged.json.incoming`);
  await ssh(password, `set -eu
test "$(sha256sum '${remoteArchive}.incoming' | awk '{print $1}')" = '${ARCHIVE_SHA256}'
mv '${remoteArchive}.incoming' '${remoteArchive}'
mv '${REMOTE_STAGE}/staged.json.incoming' '${REMOTE_STAGE}/staged.json'
chmod 0600 '${remoteArchive}' '${REMOTE_STAGE}/staged.json'
sync
`);
  csrfToken = await login(context, password);
  step('api_session_refreshed_after_staging=yes');
  const stagedStatus = requireApiOk(
    await api(context, csrfToken, '/api/system-update/status'),
    'replacement staged status',
  );
  if (stagedStatus.staged?.version !== SYSTEM_VERSION || stagedStatus.staged?.destructive !== true) {
    fail('replacement staged status mismatch');
  }

  requireApiOk(
    await api(context, csrfToken, '/api/system-update/raw-enabled', 'POST', { enabled: true }),
    'enable raw updates',
    false,
  );
  step(`starting ${SYSTEM_VERSION} through stock system-update API`);
  try {
    const installed = await api(context, csrfToken, '/api/system-update/install', 'POST', {});
    requireApiOk(installed, 'replacement install');
  } catch (error) {
    step(`install request disconnected after updater launch: ${error.name}`);
  }

  ({ context, baseURL } = await waitForCycle(context, `${SYSTEM_VERSION} update`));
  csrfToken = await login(context, password);
  step(`after_raw_update_api=${baseURL}`);
  if (baseURL !== `https://${TARGET_IP}`) fail(`${SYSTEM_VERSION} did not restore HTTPS`);
  const afterVersion = requireApiOk(
    await api(context, csrfToken, '/api/system-update/version'),
    'replacement system version',
  ).current;
  if (afterVersion.version !== SYSTEM_VERSION) fail(`replacement version mismatch: ${afterVersion.version}`);
  const appVersion = requireApiOk(
    await api(context, csrfToken, '/api/application/version'),
    'replacement app version',
  );
  if (appVersion.current !== APP_VERSION) fail(`replacement app mismatch: ${appVersion.current}`);
  await waitBootGood(context, csrfToken);
  requireApiOk(
    await api(context, csrfToken, '/api/system-update/raw-enabled', 'POST', { enabled: false }),
    'disable raw updates',
    false,
  );

  const afterSsh = await ssh(password, `set -eu
printf 'HOSTNAME=%s\\n' "$(hostname)"
printf 'HOSTNAME_FILE=%s\\n' "$(head -n 1 /etc/hostname | tr -d '\\r\\n')"
printf 'PROTO=%s\\n' "$(awk -F: '/^[[:space:]]*proto:/ { value=$2; gsub(/[[:space:]\"]/, "", value); print value; exit }' /etc/kvm/server.yaml)"
printf 'RESTORE_DONE_VALUE=%s\\n' "$(cat '${REMOTE_STAGE}/root-restore-done' 2>/dev/null || true)"
printf 'CURL=%s\\n' "$([ -x /usr/bin/curl ] && echo present || echo missing)"
printf 'OPENSSL=%s\\n' "$([ -x /usr/bin/openssl ] && echo present || echo missing)"
printf 'CA=%s\\n' "$([ -s /etc/ssl/certs/ca-certificates.crt ] && echo present || echo missing)"
printf 'RAW_MARKER=%s\\n' "$([ -e /data/hardened-system-raw-update-pending.json ] && echo present || echo cleared)"
printf 'BOOT_GOOD=%s\\n' "$([ -e /etc/kvm/system-update-boot-good.json ] && echo present || echo missing)"
printf 'KVM_SYSTEM_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/kvm_system/kvm_system | awk '{print $1}')"
printf 'KVM_SYSTEM_RUNTIME_SHA=%s\\n' "$(sha256sum /tmp/kvm_system/kvm_system | awk '{print $1}')"
printf 'LIBKVM_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm.so | awk '{print $1}')"
printf 'LIBKVM_MMF_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm_mmf.so | awk '{print $1}')"
printf 'TMP_SERVER_DL_LIB=%s\\n' "$([ -e /tmp/server/dl_lib ] && echo present || echo absent)"
printf 'S30ETH_SHA=%s\\n' "$(sha256sum /etc/init.d/S30eth | awk '{print $1}')"
printf 'KVMAPP_S30ETH_SHA=%s\\n' "$(sha256sum /kvmapp/system/init.d/S30eth | awk '{print $1}')"
printf 'SOPH_VCODEC_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_vcodec.ko | awk '{print $1}')"
printf 'SOPH_JPEG_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_jpeg.ko | awk '{print $1}')"
printf 'SOPH_VC_DRIVER_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_vc_driver.ko | awk '{print $1}')"
printf 'MODULE_VCODEC=%s\\n' "$(grep -q '^soph_vcodec ' /proc/modules && echo loaded || echo missing)"
printf 'MODULE_JPEG=%s\\n' "$(grep -q '^soph_jpeg ' /proc/modules && echo loaded || echo missing)"
printf 'MODULE_VC_DRIVER=%s\\n' "$(grep -q '^soph_vc_driver ' /proc/modules && echo loaded || echo missing)"
printf 'VCODEC_LOCK_SYMBOL=%s\\n' "$(awk '$3 == \"vcodec_lock\" && $4 == \"[soph_vcodec]\" { found=1 } END { print found ? \"present\" : \"absent\" }' /proc/kallsyms)"
printf 'JPEG_SRCVERSION=%s\\n' "$(cat /sys/module/soph_jpeg/srcversion 2>/dev/null || true)"
printf 'MAX_VENC=%s\\n' "$(cat /sys/module/soph_vc_driver/parameters/MaxVencChnNum 2>/dev/null || true)"
printf 'MAX_VDEC=%s\\n' "$(cat /sys/module/soph_vc_driver/parameters/MaxVdecChnNum 2>/dev/null || true)"
printf 'MEDIA_PROVENANCE=%s\\n' "$(grep -q '^device_acceptance=10.0.87.133-20260821T032009Z$' /mnt/system/ko/hardened-source-media-provenance.txt && echo present || echo missing)"
printf 'DNS_TOTAL=%s\\n' "$(awk '$1 == \"nameserver\" { count++ } END { print count + 0 }' /etc/resolv.conf)"
printf 'DNS_UNIQUE=%s\\n' "$(awk '$1 == \"nameserver\" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
printf 'SYSLOG_CONFIG=%s\\n' "$(grep -Fq '${REMOTE_SYSLOG_HOST}' /etc/kvm/syslog.json && echo present || echo missing)"
printf 'SYSLOG_DEFAULT=%s\\n' "$(grep -Fq -- '-R ${REMOTE_SYSLOG_HOST}:${REMOTE_SYSLOG_PORT}' /etc/default/syslogd && grep -Fq -- '-L' /etc/default/syslogd && echo configured || echo missing)"
printf 'KLOG_DEFAULT=%s\\n' "$([ -s /etc/default/klogd ] && echo present || echo missing)"
SYSLOG_PID="$(cat /var/run/syslogd.pid 2>/dev/null || true)"
printf 'SYSLOG_RUNNING=%s\\n' "$([ -n "$SYSLOG_PID" ] && kill -0 "$SYSLOG_PID" 2>/dev/null && echo yes || echo no)"
printf 'SYSLOG_CMDLINE=%s\\n' "$(tr '\\0' ' ' < "/proc/$SYSLOG_PID/cmdline" 2>/dev/null || true)"
	KVM_PID=''
	KVM_PROCESS_COUNT=0
	for PROC in /proc/[0-9]*; do
	  CMD="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
	  case "$CMD" in
	    /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_PROCESS_COUNT=$((KVM_PROCESS_COUNT + 1)); KVM_PID="\${PROC##*/}" ;;
	  esac
	done
	printf 'KVM_SYSTEM_PID=%s\\n' "$KVM_PID"
	printf 'KVM_SYSTEM_PID_FILE=%s\\n' "$(cat /tmp/kvm-system.pid 2>/dev/null || true)"
	printf 'KVM_SYSTEM_PROCESS_COUNT=%s\\n' "$KVM_PROCESS_COUNT"
if [ -n "$KVM_PID" ]; then
  printf 'KVM_SYSTEM_THREADS=%s\\n' "$(find "/proc/$KVM_PID/task" -mindepth 1 -maxdepth 1 | wc -l)"
else
  printf 'KVM_SYSTEM_THREADS=0\\n'
fi
/lib/ld-musl-riscv64v0p7_xthead.so.1 --library-path \
  /kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd \
  --list /tmp/kvm_system/kvm_system >/tmp/hardened-kvm-system-postflight.txt 2>&1
printf 'KVM_SYSTEM_LIST_RC=0\\n'
	printf 'KVM_SYSTEM_LOG_ERRORS=%s\\n' "$(grep -Eic 'Error loading|Error relocating|unsupported relocation' /tmp/kvm_system.log 2>/dev/null || true)"
	printf 'KVM_WATCHDOG_INIT=%s\\n' "$(grep -q 'adopt_single_kvm_system_process' /etc/init.d/S95nanokvm && echo present || echo missing)"
	printf 'DMESG_ALERTS=%s\\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format' || true)"
`);
  fs.writeFileSync(path.join(resultDir, `after-${SYSTEM_VERSION}.txt`), afterSsh, { mode: 0o600 });
  const newRestoreValue = afterSsh.match(/RESTORE_DONE_VALUE=([^\r\n]*)/)?.[1] || '';
  for (const expected of [
    'HOSTNAME=secondary', 'HOSTNAME_FILE=secondary', 'PROTO=https',
    'CURL=present', 'OPENSSL=present', 'CA=present',
    'RAW_MARKER=cleared', 'BOOT_GOOD=present',
    `KVM_SYSTEM_DISK_SHA=${KVM_SYSTEM_SHA256}`,
	`KVM_SYSTEM_RUNTIME_SHA=${KVM_SYSTEM_SHA256}`,
	`LIBKVM_DISK_SHA=${LIBKVM_SHA256}`, `LIBKVM_MMF_DISK_SHA=${LIBKVM_MMF_SHA256}`,
	'TMP_SERVER_DL_LIB=absent',
	`S30ETH_SHA=${S30ETH_SHA256}`, `KVMAPP_S30ETH_SHA=${S30ETH_SHA256}`,
	`SOPH_VCODEC_SHA=${SOPH_VCODEC_SHA256}`, `SOPH_JPEG_SHA=${SOPH_JPEG_SHA256}`,
	`SOPH_VC_DRIVER_SHA=${SOPH_VC_DRIVER_SHA256}`,
	'MODULE_VCODEC=loaded', 'MODULE_JPEG=loaded', 'MODULE_VC_DRIVER=loaded',
	'VCODEC_LOCK_SYMBOL=present', 'JPEG_SRCVERSION=625882D05A26BB4B2FD9A6E',
	'MAX_VENC=9', 'MAX_VDEC=9', 'MEDIA_PROVENANCE=present',
	'SYSLOG_CONFIG=present', 'SYSLOG_DEFAULT=configured', 'KLOG_DEFAULT=present',
	'SYSLOG_RUNNING=yes', `-R ${REMOTE_SYSLOG_HOST}:${REMOTE_SYSLOG_PORT}`, '-L',
	'KVM_SYSTEM_PROCESS_COUNT=1', 'KVM_SYSTEM_LIST_RC=0', 'KVM_SYSTEM_LOG_ERRORS=0',
	'KVM_WATCHDOG_INIT=present', 'DMESG_ALERTS=0',
  ]) {
    if (!afterSsh.includes(expected)) fail(`replacement postflight missing ${expected}`);
  }
  if (!/^KVM_SYSTEM_PID=[0-9]+$/m.test(afterSsh)) fail('kvm_system process is not running after replacement');
  const kvmPid = afterSsh.match(/^KVM_SYSTEM_PID=([0-9]+)$/m)?.[1] || '';
  const kvmPidFile = afterSsh.match(/^KVM_SYSTEM_PID_FILE=([0-9]+)$/m)?.[1] || '';
  if (kvmPidFile !== kvmPid) fail(`kvm_system PID file mismatch: process=${kvmPid} file=${kvmPidFile}`);
  const kvmThreads = Number(afterSsh.match(/^KVM_SYSTEM_THREADS=([0-9]+)$/m)?.[1] || '0');
  if (kvmThreads < 2) fail(`kvm_system thread count is unexpectedly low: ${kvmThreads}`);
  const dnsTotal = afterSsh.match(/^DNS_TOTAL=([0-9]+)$/m)?.[1] || '';
  const dnsUnique = afterSsh.match(/^DNS_UNIQUE=([0-9]+)$/m)?.[1] || '';
  if (!dnsTotal || dnsTotal !== dnsUnique) {
    fail(`static DNS contains duplicates: total=${dnsTotal || 'missing'} unique=${dnsUnique || 'missing'}`);
  }
  if (!newRestoreValue || newRestoreValue === oldRestoreValue) {
    fail(`root restore marker was not refreshed by ${SYSTEM_VERSION}`);
  }

  const updateCheck = requireApiOk(
    await api(context, csrfToken, '/api/system-update/check'),
    'replacement online update check',
  );
  if (updateCheck.error) fail(`replacement online update check error: ${updateCheck.error}`);
  requireApiOk(await api(context, csrfToken, '/api/vm/hdmi'), 'replacement HDMI API');
  const syslogConfigAfter = requireApiOk(
    await api(context, csrfToken, '/api/system-log/config'),
    'remote syslog config after raw update',
  ).config;
  if (
    syslogConfigAfter?.remoteEnabled !== true
    || syslogConfigAfter?.remoteHost !== REMOTE_SYSLOG_HOST
    || syslogConfigAfter?.remotePort !== REMOTE_SYSLOG_PORT
  ) {
    fail('remote syslog API configuration did not survive raw update');
  }
  requireApiOk(
    await api(context, csrfToken, '/api/system-log/test', 'POST', {}),
    'remote syslog test after raw update',
    false,
  );

  step(`system=${afterVersion.version}`);
  step(`app=${appVersion.current}`);
  step(`hostname=secondary`);
  step(`api=https`);
  step(`restore_marker_refreshed=${newRestoreValue}`);
  step(`kvm_system_sha256=${KVM_SYSTEM_SHA256}`);
  step(`kvm_system_threads=${kvmThreads}`);
  step('source_media_modules=loaded-and-verified');
  step(`dns_nameservers=${dnsTotal}/${dnsUnique}`);
  step(`remote_syslog_preserved=${REMOTE_SYSLOG_HOST}:${REMOTE_SYSLOG_PORT}/udp`);
  step(`SUCCESS: ${SYSTEM_VERSION} replacement installed and regression gates passed`);
  await context.dispose();
}

main().catch((error) => {
  try {
    step(`FAILED: ${error.message}`);
  } catch {}
  process.exitCode = 1;
});
