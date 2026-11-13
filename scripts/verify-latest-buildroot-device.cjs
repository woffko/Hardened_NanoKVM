#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const CryptoJS = require('../web/node_modules/crypto-js');
const { request } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = process.env.TARGET_IP || '10.0.87.133';
const EXPECTED_SYSTEM = process.env.EXPECTED_SYSTEM_VERSION || '0.3.0-raw.10';
const EXPECTED_APP = process.env.EXPECTED_APP_VERSION || '2.0.40';
const EXPECTED_BACKEND_SHA256 = process.env.EXPECTED_BACKEND_SHA256
  || '04e50160903434a1086ae337c3522ea93c1f2292e01833ca24db1de70882bdb4';
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
const EXPECTED_ED25519 = process.env.EXPECTED_ED25519
  || 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const RECOVERY_FIRST_BOOT = process.env.RECOVERY_FIRST_BOOT === '1';
const EXPECTED_ETH_MAC = (process.env.EXPECTED_ETH_MAC || '').toLowerCase();
const EXPECTED_CONFIG_PROTO = process.env.EXPECTED_CONFIG_PROTO || '';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `postflight-${EXPECTED_SYSTEM}-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');
const knownHostsPath = path.join(resultDir, 'known_hosts');

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
  const fingerprintText = fingerprints.toString('utf8');
  if (!fingerprintText.includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    fail('post-update ED25519 fingerprint does not match the physically confirmed device');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });
  step(`ssh_ed25519=${EXPECTED_ED25519}`);
}

async function ssh(password, command) {
  const output = await runProcess(
    SSHPASS,
    [
      '-d', '3', 'ssh',
      '-o', 'ConnectTimeout=10',
      '-o', 'ConnectionAttempts=1',
      '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no',
      '-o', 'StrictHostKeyChecking=yes',
      '-o', `UserKnownHostsFile=${knownHostsPath}`,
      `root@${TARGET_IP}`,
      command,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
  return output.toString('utf8');
}

async function connectApi() {
  for (const baseURL of [`https://${TARGET_IP}`, `http://${TARGET_IP}`]) {
    const context = await request.newContext({
      baseURL,
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: { Accept: 'application/json' },
      timeout: 30000,
    });
    try {
      const response = await context.get('/api/health', { timeout: 5000 });
      const json = await response.json();
      if (response.ok() && json?.code === 0 && json?.data?.status === 'ok') {
        return { context, baseURL };
      }
    } catch {}
    await context.dispose();
  }
  fail('neither HTTPS nor HTTP health endpoint is reachable');
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
    fail(`HTTP API login failed: code=${json?.code ?? 'unknown'} message=${json?.msg ?? response.status()}`);
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
  return { status: response.status(), json };
}

async function uploadAndRunScript(context, csrfToken, name, content) {
  const upload = await context.post('/api/vm/script/upload', {
    headers: { 'x-csrf-token': csrfToken },
    multipart: {
      file: {
        name,
        mimeType: 'application/x-sh',
        buffer: Buffer.from(content, 'utf8'),
      },
    },
    timeout: 60000,
  });
  const uploadJson = await upload.json();
  if (!upload.ok() || uploadJson?.code !== 0) {
    fail(`script upload failed: ${uploadJson?.msg ?? upload.status()}`);
  }
  const run = await api(context, csrfToken, '/api/vm/script/run', 'POST', {
    name,
    type: 'foreground',
  });
  if (run.status >= 400 || run.json?.code !== 0) {
    fail(`script execution failed: ${run.json?.msg ?? run.status}`);
  }
  return run.json?.data?.log ?? '';
}

async function deleteScript(context, csrfToken, name) {
  const response = await context.delete('/api/vm/script', {
    headers: { 'x-csrf-token': csrfToken },
    data: { name },
    timeout: 30000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) {
    fail(`script deletion failed: ${json?.msg ?? response.status()}`);
  }
}

function requireApiOk(result, operation) {
  if (result.status >= 400 || result.json?.code !== 0 || !result.json?.data) {
    fail(`${operation} failed: code=${result.json?.code ?? 'unknown'} message=${result.json?.msg ?? result.status}`);
  }
  return result.json.data;
}

function parseFields(text) {
  const fields = new Map();
  for (const line of text.split(/\r?\n/)) {
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    fields.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return fields;
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing device verification without --confirm-device ${TARGET_IP}`);
  }
  const repairPasswords = process.argv.includes('--repair-passwords');
  const repairSshPolicy = process.argv.includes('--repair-ssh-policy');
  const diagnoseSshPolicyOnly = process.argv.includes('--diagnose-ssh-policy-only');
  const disableRawAfterVerify = process.env.DISABLE_RAW_UPDATES_AFTER_VERIFY === '1';
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  step('preparing isolated post-update SSH trust');
  await prepareKnownHosts();
  step('connecting to the active HTTP or HTTPS API');
  const { context, baseURL } = await connectApi();
  try {
    step(`api_base=${baseURL}`);
    let csrfToken = await login(context, password);
    step('api_login=ok');

    if (diagnoseSshPolicyOnly) {
      const diagnosticName = 'hardened-ssh-policy-diagnose.sh';
      const diagnostic = `#!/bin/sh
set -eu
printf 'ROOT_SHADOW_STATE='
awk -F: '$1 == "root" { if ($2 == "") print "empty"; else if ($2 ~ /^[!*]/) print "locked"; else print "hash-present" }' /etc/shadow
printf 'ROOT_SHELL='
awk -F: '$1 == "root" { print $7 }' /etc/passwd
sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|usepam) ' || true
`;
      const diagnosticLog = await uploadAndRunScript(
        context,
        csrfToken,
        diagnosticName,
        diagnostic,
      );
      fs.writeFileSync(path.join(resultDir, 'sshd-policy-diagnostic.txt'), diagnosticLog, { mode: 0o600 });
      await deleteScript(context, csrfToken, diagnosticName);
      for (const line of diagnosticLog.trim().split(/\r?\n/)) {
        if (line) step(`sshd=${line}`);
      }
      step('SUCCESS: live sshd policy diagnosed without mutation');
      return;
    }

    const version = requireApiOk(
      await api(context, csrfToken, '/api/system-update/version'),
      'system version',
    ).current;
    const status = requireApiOk(
      await api(context, csrfToken, '/api/system-update/status'),
      'system status',
    );
    const app = requireApiOk(
      await api(context, csrfToken, '/api/application/version'),
      'application version',
    );
    const raw = requireApiOk(
      await api(context, csrfToken, '/api/system-update/raw-enabled'),
      'raw update flag',
    );
    const setup = requireApiOk(
      await api(context, csrfToken, '/api/auth/setup'),
      'first-account setup state',
    );
    requireApiOk(await api(context, csrfToken, '/api/vm/hdmi'), 'HDMI API');

    const updateCheck = await api(context, csrfToken, '/api/system-update/check');
    const updateCheckError = updateCheck.json?.data?.error ||
      (updateCheck.json?.code === 0 ? '' : updateCheck.json?.msg || `HTTP ${updateCheck.status}`);

    step('reading rootfs, service, restore, and network state over SSH');
    const sshCommand = `set -eu
printf 'UID=%s\\n' "$(id -u)"
printf 'HOSTNAME=%s\\n' "$(hostname)"
printf 'SYSTEM_VERSION=%s\\n' "$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^" ]*\\)".*/\\1/p' /etc/kvm/system-version.json | head -n 1)"
printf 'APP_VERSION=%s\\n' "$(cat /kvmapp/version)"
printf 'KERNEL=%s\\n' "$(uname -r)"
printf 'OS_PRETTY=%s\\n' "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"')"
printf 'ROOT_MOUNT=%s\\n' "$(awk '$2 == "/" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'BOOT_MOUNT=%s\\n' "$(awk '$2 == "/boot" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'DATA_MOUNT=%s\\n' "$(awk '$2 == "/data" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'ETH_MAC=%s\\n' "$(cat /sys/class/net/eth0/address 2>/dev/null || true)"
printf 'P1_SECTORS=%s\\n' "$(cat /sys/class/block/mmcblk0p1/size 2>/dev/null || true)"
printf 'P2_SECTORS=%s\\n' "$(cat /sys/class/block/mmcblk0p2/size 2>/dev/null || true)"
printf 'P3_SECTORS=%s\\n' "$(cat /sys/class/block/mmcblk0p3/size 2>/dev/null || true)"
printf 'AVAHI_STATUS=%s\\n' "$(/usr/sbin/avahi-daemon -c >/dev/null 2>&1 && echo running || echo stopped)"
printf 'AVAHI_SOCKET_MODE=%s\\n' "$([ -S /run/avahi-daemon/socket ] && stat -c '%a' /run/avahi-daemon/socket || echo absent)"
BACKEND_PID=''
if [ -r /tmp/nanokvm-server.pid ]; then
  CANDIDATE_PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
  if [ -n "$CANDIDATE_PID" ] && kill -0 "$CANDIDATE_PID" 2>/dev/null; then BACKEND_PID="$CANDIDATE_PID"; fi
fi
KVM_SYSTEM_PID=''
for PROC in /proc/[0-9]*; do
  CMDLINE="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMDLINE" in
    *'/kvm_system/kvm_system'*) KVM_SYSTEM_PID="\${PROC##*/}"; break ;;
  esac
done
printf 'BACKEND_PID=%s\\n' "$BACKEND_PID"
printf 'KVM_SYSTEM_PID=%s\\n' "$KVM_SYSTEM_PID"
printf 'BACKEND_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/NanoKVM-Server 2>/dev/null | awk '{print $1}')"
printf 'BACKEND_RUNTIME_SHA=%s\\n' "$(sha256sum /tmp/server/NanoKVM-Server 2>/dev/null | awk '{print $1}')"
printf 'LIBKVM_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm.so 2>/dev/null | awk '{print $1}')"
printf 'LIBKVM_MMF_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/dl_lib/libkvm_mmf.so 2>/dev/null | awk '{print $1}')"
printf 'TMP_SERVER_DL_LIB=%s\\n' "$([ -e /tmp/server/dl_lib ] && echo present || echo absent)"
printf 'WEB_INDEX=%s\\n' "$([ -f /kvmapp/server/web/index.html ] && echo present || echo missing)"
printf 'RESTORE_DONE=%s\\n' "$([ -f /data/.hardened-kvmcache/system-update/root-restore-done ] && echo present || echo missing)"
printf 'RAW_MARKER=%s\\n' "$([ -f /data/hardened-system-raw-update-pending.json ] && echo present || echo cleared)"
printf 'BOOT_GOOD=%s\\n' "$([ -f /etc/kvm/system-update-boot-good.json ] && echo present || echo missing)"
printf 'CONFIG_PROTO=%s\\n' "$(awk -F: '/^[[:space:]]*proto:/ { value=$2; gsub(/[[:space:]\"]/, "", value); print value; exit }' /etc/kvm/server.yaml 2>/dev/null || true)"
printf 'DNS_CONFIG=%s\\n' "$(awk 'BEGIN { first=1 } /^nameserver / { if (!first) printf ","; printf "%s", $2; first=0 } END { print "" }' /etc/resolv.conf 2>/dev/null || true)"
printf 'DNS_TOTAL=%s\\n' "$(awk '$1 == \"nameserver\" { count++ } END { print count + 0 }' /etc/resolv.conf)"
printf 'DNS_UNIQUE=%s\\n' "$(awk '$1 == \"nameserver\" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
printf 'S30ETH_SHA=%s\\n' "$(sha256sum /etc/init.d/S30eth | awk '{print $1}')"
printf 'KVMAPP_S30ETH_SHA=%s\\n' "$(sha256sum /kvmapp/system/init.d/S30eth | awk '{print $1}')"
printf 'SOPH_VCODEC_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_vcodec.ko | awk '{print $1}')"
printf 'SOPH_JPEG_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_jpeg.ko | awk '{print $1}')"
printf 'SOPH_VC_DRIVER_SHA=%s\\n' "$(sha256sum /mnt/system/ko/soph_vc_driver.ko | awk '{print $1}')"
PRESERVE_ROOT=/data/.hardened-kvmcache/system-update/preserve/root
printf 'PRESERVE_ROOT=%s\\n' "$([ -d "$PRESERVE_ROOT" ] && echo present || echo missing)"
printf 'PRESERVE_ETC_SSH=%s\\n' "$([ -d "$PRESERVE_ROOT/etc/ssh" ] && echo present || echo missing)"
printf 'PRESERVE_SSH_FILES=%s\\n' "$(find "$PRESERVE_ROOT/etc/ssh" -maxdepth 1 -type f 2>/dev/null | wc -l)"
printf 'CURRENT_SSH_FILES=%s\\n' "$(find /etc/ssh -maxdepth 1 -type f 2>/dev/null | wc -l)"
printf 'PRESERVED_HOSTNAME=%s\\n' "$(cat "$PRESERVE_ROOT/etc/hostname" 2>/dev/null || true)"
printf 'PRESERVED_PROTO=%s\\n' "$(awk -F: '/^[[:space:]]*proto:/ { value=$2; gsub(/[[:space:]\"]/, "", value); print value; exit }' "$PRESERVE_ROOT/etc/kvm/server.yaml" 2>/dev/null || true)"
printf 'RESTORE_FAILURE_LINES=%s\\n' "$(grep -Eic 'failed|failure' /data/hardened-system-raw-update.log 2>/dev/null || true)"
printf 'CURL_BIN=%s\\n' "$([ -x /usr/bin/curl ] && echo present || echo missing)"
printf 'CA_BUNDLE=%s\\n' "$([ -s /etc/ssl/certs/ca-certificates.crt ] && echo present || echo missing)"
printf 'OPENSSL_BIN=%s\\n' "$([ -x /usr/bin/openssl ] && echo present || echo missing)"
GATEWAY="$(ip route show default 2>/dev/null | awk 'NR == 1 { print $3 }')"
printf 'DEFAULT_GATEWAY=%s\\n' "$GATEWAY"
if [ -n "$GATEWAY" ] && ping -c 1 -W 2 "$GATEWAY" >/dev/null 2>&1; then GATEWAY_PING=ok; else GATEWAY_PING=failed; fi
printf 'GATEWAY_PING=%s\\n' "$GATEWAY_PING"
GITHUB_DNS="$(getent hosts github.com 2>/dev/null | head -n 1 | awk '{print $1}' || true)"
if [ -z "$GITHUB_DNS" ] && [ -x /bin/busybox ]; then
  GITHUB_DNS="$(/bin/busybox nslookup github.com 2>/dev/null | awk '/^Address [0-9]*: / { print $3; exit } /^Address: / { print $2; exit }')"
fi
printf 'GITHUB_DNS=%s\\n' "$GITHUB_DNS"
if grep -q '^soph_sys ' /proc/modules && grep -q '^soph_vcodec ' /proc/modules && grep -q '^soph_jpeg ' /proc/modules && grep -q '^soph_vc_driver ' /proc/modules && grep -q '^soph_vi ' /proc/modules; then CRITICAL_MODULES=ok; else CRITICAL_MODULES=missing; fi
printf 'CRITICAL_MODULES=%s\\n' "$CRITICAL_MODULES"
printf 'DMESG_ALERTS=%s\\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:|Unknown symbol|disagrees about version|invalid module format' || true)"
printf 'RAW_LOG_TAIL_BEGIN\\n'
tail -n 30 /data/hardened-system-raw-update.log 2>/dev/null || true
printf 'RAW_LOG_TAIL_END\\n'
`;
    let sshText;
    try {
      sshText = await ssh(password, sshCommand);
    } catch (error) {
      if (!repairPasswords || error.exitCode !== 5) throw error;
      step('root SSH password mismatch confirmed; synchronizing web and root through /api/auth/password');
      const passwordUpdate = await api(
        context,
        csrfToken,
        '/api/auth/password',
        'POST',
        {
          username: 'admin',
          password: encryptPassword(password),
        },
      );
      if (passwordUpdate.status >= 400 || passwordUpdate.json?.code !== 0) {
        fail(`password synchronization failed: ${passwordUpdate.json?.msg ?? passwordUpdate.status}`);
      }
      step('password synchronization API completed; re-authenticating');
      csrfToken = await login(context, password);
      if (!csrfToken) fail('post-password-change API login failed');
      try {
        sshText = await ssh(password, sshCommand);
        step('root_ssh_password_repaired=yes');
      } catch (secondError) {
        if (!repairSshPolicy || secondError.exitCode !== 5) throw secondError;
        step('root password is synchronized but sshd still rejects it; inspecting effective sshd policy');
        const diagnosticName = 'hardened-ssh-policy-diagnose.sh';
        const diagnostic = `#!/bin/sh
set -eu
printf 'ROOT_SHADOW_STATE='
awk -F: '$1 == "root" { if ($2 == "") print "empty"; else if ($2 ~ /^[!*]/) print "locked"; else print "hash-present" }' /etc/shadow
printf 'ROOT_SHELL='
awk -F: '$1 == "root" { print $7 }' /etc/passwd
sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|usepam) ' || true
`;
        const diagnosticLog = await uploadAndRunScript(
          context,
          csrfToken,
          diagnosticName,
          diagnostic,
        );
        fs.writeFileSync(path.join(resultDir, 'sshd-policy-before.txt'), diagnosticLog, { mode: 0o600 });
        await deleteScript(context, csrfToken, diagnosticName);

        step('installing explicit root password SSH policy and restarting sshd');
        const repairName = 'hardened-ssh-policy-repair.sh';
        const repair = `#!/bin/sh
set -eu
CONFIG=/etc/ssh/sshd_config
TMP=/etc/ssh/sshd_config.hardened.$$
mkdir -p /etc/ssh
touch "$CONFIG"
awk '
  /^[[:space:]]*PermitRootLogin[[:space:]]/ { next }
  /^[[:space:]]*PasswordAuthentication[[:space:]]/ { next }
  /^[[:space:]]*KbdInteractiveAuthentication[[:space:]]/ { next }
  /^[[:space:]]*PermitEmptyPasswords[[:space:]]/ { next }
  { print }
' "$CONFIG" > "$TMP"
cat >> "$TMP" <<'EOF'

# Hardened NanoKVM managed root account policy.
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PermitEmptyPasswords no
EOF
chmod 0600 "$TMP"
sshd -t -f "$TMP"
mv "$TMP" "$CONFIG"
/etc/init.d/S50sshd restart
sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords) '
`;
        const repairLog = await uploadAndRunScript(context, csrfToken, repairName, repair);
        fs.writeFileSync(path.join(resultDir, 'sshd-policy-after.txt'), repairLog, { mode: 0o600 });
        await deleteScript(context, csrfToken, repairName);
        sshText = await ssh(password, sshCommand);
        step('root_ssh_policy_repaired=yes');
      }
    }
    fs.writeFileSync(path.join(resultDir, 'ssh-postflight.txt'), sshText, { mode: 0o600 });
    const fields = parseFields(sshText);

    step(`system=${version.version}`);
    step(`base=${version.baseVersion}`);
    step(`userspace=${version.rootfsVersion}`);
    step(`kernel=${version.kernelVersion}`);
    step(`app=${app.current}`);
    step(`pending=${status.pending ? 'yes' : 'no'}`);
    step(`boot_health=${status.bootHealth?.healthy === true ? 'healthy' : 'not-healthy-or-cleared'}`);
    step(`raw_enabled=${raw.enabled}`);
    step(`setup_required=${setup.required}`);
    step(`update_check_error=${updateCheckError || 'none'}`);
    for (const name of [
      'HOSTNAME', 'ROOT_MOUNT', 'BOOT_MOUNT', 'DATA_MOUNT', 'RESTORE_DONE',
      'ETH_MAC', 'P1_SECTORS', 'P2_SECTORS', 'P3_SECTORS', 'AVAHI_STATUS',
      'AVAHI_SOCKET_MODE',
      'RAW_MARKER', 'BOOT_GOOD', 'CONFIG_PROTO', 'DNS_CONFIG', 'DNS_TOTAL', 'DNS_UNIQUE',
      'S30ETH_SHA', 'KVMAPP_S30ETH_SHA', 'SOPH_VCODEC_SHA', 'SOPH_JPEG_SHA',
      'SOPH_VC_DRIVER_SHA', 'PRESERVE_ROOT',
      'PRESERVE_ETC_SSH', 'PRESERVE_SSH_FILES', 'CURRENT_SSH_FILES',
      'PRESERVED_HOSTNAME', 'PRESERVED_PROTO', 'RESTORE_FAILURE_LINES',
      'CURL_BIN', 'CA_BUNDLE', 'OPENSSL_BIN', 'DEFAULT_GATEWAY', 'GATEWAY_PING',
      'GITHUB_DNS', 'CRITICAL_MODULES', 'DMESG_ALERTS',
      'BACKEND_DISK_SHA', 'BACKEND_RUNTIME_SHA', 'LIBKVM_DISK_SHA',
      'LIBKVM_MMF_DISK_SHA', 'TMP_SERVER_DL_LIB',
    ]) {
      step(`${name.toLowerCase()}=${fields.get(name) ?? ''}`);
    }

    if (version.version !== EXPECTED_SYSTEM || fields.get('SYSTEM_VERSION') !== EXPECTED_SYSTEM) {
      fail('postflight system version mismatch');
    }
    if (app.current !== EXPECTED_APP || fields.get('APP_VERSION') !== EXPECTED_APP) {
      fail('postflight app version mismatch');
    }
    if (!version.rootfsVersion?.includes('Buildroot 2026.05.1') || !fields.get('OS_PRETTY')?.includes('Buildroot 2026.05.1')) {
      fail('postflight Buildroot userspace mismatch');
    }
    if (fields.get('UID') !== '0' || !fields.get('BACKEND_PID') || !fields.get('KVM_SYSTEM_PID')) {
      fail('postflight SSH or runtime process check failed');
    }
    if (fields.get('WEB_INDEX') !== 'present') fail('postflight web root is missing');
    if (RECOVERY_FIRST_BOOT) {
      if (setup.required !== false) fail('recovery first-account setup is incomplete');
      if (status.pending || raw.enabled !== false) fail('recovery update state is not clean');
      if (fields.get('RESTORE_DONE') !== 'missing' || fields.get('RAW_MARKER') !== 'cleared') {
        fail('recovery image unexpectedly contains raw-update restore state');
      }
      if (!fields.get('ROOT_MOUNT')?.startsWith('/dev/mmcblk0p2:ext4:')) {
        fail('recovery rootfs mount mismatch');
      }
      if (!fields.get('BOOT_MOUNT')?.startsWith('/dev/mmcblk0p1:vfat:')) {
        fail('recovery boot mount mismatch');
      }
      if (!fields.get('DATA_MOUNT')?.startsWith('/dev/mmcblk0p3:exfat:')) {
        fail('recovery data mount mismatch');
      }
      if (!EXPECTED_ETH_MAC || fields.get('ETH_MAC')?.toLowerCase() !== EXPECTED_ETH_MAC) {
        fail('recovery Ethernet MAC mismatch');
      }
      const effectiveProto = fields.get('CONFIG_PROTO') || new URL(baseURL).protocol.slice(0, -1);
      if (EXPECTED_CONFIG_PROTO && effectiveProto !== EXPECTED_CONFIG_PROTO) {
        fail('recovery HTTP/HTTPS mode mismatch');
      }
      if (fields.get('P1_SECTORS') !== '32768') fail('recovery boot partition size mismatch');
      if (Number(fields.get('P2_SECTORS') || 0) < 15_967_232) {
        fail('recovery rootfs partition was not expanded');
      }
      if (Number(fields.get('P3_SECTORS') || 0) <= 0) fail('recovery data partition is missing');
      if (fields.get('AVAHI_STATUS') !== 'running') fail('recovery Avahi daemon is not running');
      if (!['600', 'absent'].includes(fields.get('AVAHI_SOCKET_MODE'))) {
        fail('recovery Avahi socket mode mismatch');
      }
    } else {
      if (fields.get('RESTORE_DONE') !== 'present') {
        fail('postflight preserved root configuration was not restored');
      }
      if (fields.get('RAW_MARKER') !== 'cleared' || fields.get('BOOT_GOOD') !== 'present') {
        fail('postflight boot-good confirmation is incomplete');
      }
    }
    if (fields.get('CRITICAL_MODULES') !== 'ok') {
      fail('postflight critical media modules are not all loaded');
    }
    for (const [field, expected] of [
      ['S30ETH_SHA', EXPECTED_S30ETH_SHA256],
      ['KVMAPP_S30ETH_SHA', EXPECTED_S30ETH_SHA256],
      ['SOPH_VCODEC_SHA', EXPECTED_SOPH_VCODEC_SHA256],
      ['SOPH_JPEG_SHA', EXPECTED_SOPH_JPEG_SHA256],
      ['SOPH_VC_DRIVER_SHA', EXPECTED_SOPH_VC_DRIVER_SHA256],
    ]) {
      if (fields.get(field) !== expected) fail(`postflight ${field} mismatch`);
    }
    if (!fields.get('DNS_TOTAL') || fields.get('DNS_TOTAL') !== fields.get('DNS_UNIQUE')) {
      fail(`postflight DNS duplicate count ${fields.get('DNS_TOTAL')}/${fields.get('DNS_UNIQUE')}`);
    }
    if (fields.get('DMESG_ALERTS') !== '0') fail('postflight kernel alerts detected');
    if (
      fields.get('BACKEND_DISK_SHA') !== EXPECTED_BACKEND_SHA256
      || fields.get('BACKEND_RUNTIME_SHA') !== EXPECTED_BACKEND_SHA256
    ) {
      fail('postflight backend provenance mismatch');
    }
    if (
      fields.get('LIBKVM_DISK_SHA') !== EXPECTED_LIBKVM_SHA256
      || fields.get('LIBKVM_MMF_DISK_SHA') !== EXPECTED_LIBKVM_MMF_SHA256
      || fields.get('TMP_SERVER_DL_LIB') !== 'absent'
    ) {
      fail('postflight native library provenance mismatch');
    }
    if (disableRawAfterVerify) {
      const disabled = await api(
        context,
        csrfToken,
        '/api/system-update/raw-enabled',
        'POST',
        { enabled: false },
      );
      if (disabled.status >= 400 || disabled.json?.code !== 0) {
        fail(`failed to disable raw updates: ${disabled.json?.msg ?? disabled.status}`);
      }
      const rawAfter = requireApiOk(
        await api(context, csrfToken, '/api/system-update/raw-enabled'),
        'raw update flag after disable',
      );
      if (rawAfter.enabled !== false) fail('raw updates remained enabled after disable');
      step('raw_updates_disabled_after_verify=yes');
    }
    step('SUCCESS: candidate boot and core runtime verified');
  } finally {
    await context.dispose();
  }
}

main().catch((error) => {
  try {
    step(`FAILED: ${error.message}`);
  } catch {}
  process.exitCode = 1;
});
