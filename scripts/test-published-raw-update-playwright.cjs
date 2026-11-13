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
const VERSION = '0.2.23-raw.1';
const EXPECTED_APP_VERSION = '2.0.32';
const EXPECTED_SHA256 = 'd7d50d279619f5a964c7367a3cd506385a423c1751c79220e6dc03ab5ca4b458';
const ARCHIVE = path.join(ROOT, 'build/system-updates', `hardened-nanokvm-system-${VERSION}.tar.gz`);
const CANDIDATE_VERSION = '0.3.0-raw.1';
const CANDIDATE_APP_VERSION = '2.0.34';
const CANDIDATE_SHA256 = '6f551a605ae6e06e1df39f81d349f81e9f8bc34d8b738e5bac56ec328e3e21d0';
const CANDIDATE_DIR = path.join(ROOT, 'build/latestbuildroot', `raw-system-update-${CANDIDATE_VERSION}`, 'artifacts');
const CANDIDATE_ARCHIVE = path.join(CANDIDATE_DIR, `hardened-nanokvm-system-${CANDIDATE_VERSION}.tar.gz`);
const CANDIDATE_METADATA = path.join(CANDIDATE_DIR, 'system-latest.json');
const CANDIDATE_SIGNATURE = path.join(CANDIDATE_DIR, 'system-latest.json.sig');
const UPDATE_PUBLIC_KEY = path.join(ROOT, 'kvmapp/system/keys/system-update-signing.pub.pem');
const VERIFY_METADATA = path.join(ROOT, 'scripts/verify-system-update-metadata.sh');
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const REMOTE_STAGE = '/data/.hardened-kvmcache/system-update';
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `two-phase-${CANDIDATE_VERSION}-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');
const workDir = path.join(resultDir, 'work');

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

async function sha256File(filename) {
  const hash = crypto.createHash('sha256');
  const stream = fs.createReadStream(filename);
  for await (const chunk of stream) hash.update(chunk);
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
    if (secretInput !== undefined) {
      child.stdio[3].end(secretInput);
    }
    if (input !== undefined && child.stdin) {
      child.stdin.end(input);
    } else if (child.stdin) {
      child.stdin.end();
    }
  });
}

const sshOptions = [
  '-o', 'ConnectTimeout=10',
  '-o', 'ConnectionAttempts=1',
  '-o', 'PreferredAuthentications=password,keyboard-interactive',
  '-o', 'PubkeyAuthentication=no',
  '-o', 'StrictHostKeyChecking=yes',
];

async function ssh(password, command) {
  const output = await runProcess(
    SSHPASS,
    ['-d', '3', 'ssh', ...sshOptions, `root@${TARGET_IP}`, command],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
  return output.toString('utf8');
}

async function sshBinary(password, command) {
  return runProcess(
    SSHPASS,
    ['-d', '3', 'ssh', ...sshOptions, `root@${TARGET_IP}`, command],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
}

async function sshWithInput(password, command, input) {
  return runProcess(
    SSHPASS,
    ['-d', '3', 'ssh', ...sshOptions, `root@${TARGET_IP}`, command],
    input,
    Buffer.from(`${password}\n`, 'utf8'),
  );
}

async function scp(password, localPath, remotePath) {
  await runProcess(
    SSHPASS,
    ['-d', '3', 'scp', '-O', ...sshOptions, localPath, `root@${TARGET_IP}:${remotePath}`],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
}

async function createApiContext() {
  return request.newContext({
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Accept: 'application/json' },
    timeout: 60 * 60 * 1000,
  });
}

async function login(apiContext, password) {
  const encryptedPassword = encodeURIComponent(
    CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString(),
  );
  const response = await apiContext.post('/api/auth/login', {
    data: { username: 'admin', password: encryptedPassword },
    timeout: 30000,
  });
  let json;
  try {
    json = await response.json();
  } catch {
    fail(`HTTPS login returned non-JSON status ${response.status()}`);
  }
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) {
    const error = new Error(
      `HTTPS login failed: code=${json?.code ?? 'unknown'} message=${json?.msg ?? response.status()}`,
    );
    error.apiCode = json?.code;
    throw error;
  }
  const setCookie = response.headers()['set-cookie'] ?? '';
  if (!setCookie.includes('nano-kvm-token=')) {
    fail('HTTPS login did not receive the session cookie');
  }
  return json.data.csrfToken;
}

async function synchronizeWebAccount(password) {
  const python = [
    'import bcrypt, json, sys',
    'password = sys.stdin.buffer.readline().rstrip(b"\\r\\n")',
    'hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12)).decode("ascii")',
    'sys.stdout.write(json.dumps({"username": "admin", "password": hashed}) + "\\n")',
  ].join('; ');
  const accountRecord = await runProcess(
    '/usr/bin/python3',
    ['-c', python],
    Buffer.from(`${password}\n`, 'utf8'),
  );
  const parsed = JSON.parse(accountRecord.toString('utf8'));
  if (parsed.username !== 'admin' || !parsed.password?.startsWith('$2')) {
    fail('generated web account record is invalid');
  }
  await sshWithInput(
    password,
    `set -eu
umask 077
TMP=/etc/kvm/pwd.new.$$
trap 'rm -f "$TMP"' EXIT HUP INT TERM
cat > "$TMP"
chmod 0600 "$TMP"
mv "$TMP" /etc/kvm/pwd
trap - EXIT HUP INT TERM
sync
`,
    accountRecord,
  );
}

async function api(apiContext, csrfToken, pathname, method = 'GET', body = undefined) {
  const headers = {};
  if (method !== 'GET') headers['x-csrf-token'] = csrfToken;
  const response = await apiContext.fetch(pathname, {
    method,
    headers,
    data: body,
    timeout: 60 * 60 * 1000,
  });
  let json;
  try {
    json = await response.json();
  } catch {
    fail(`API returned non-JSON status ${response.status()}`);
  }
  return { httpStatus: response.status(), json };
}

function requireApiOk(result, operation) {
  if (!result || result.httpStatus >= 400 || result.json?.code !== 0) {
    const code = result?.json?.code ?? 'unknown';
    const message = result?.json?.msg ?? `HTTP ${result?.httpStatus ?? 'unknown'}`;
    fail(`${operation} failed: code=${code} message=${message}`);
  }
  return result.json.data;
}

async function healthOnline(context) {
  try {
    const response = await context.get('/api/health', {
      failOnStatusCode: false,
      timeout: 5000,
    });
    if (!response.ok()) return false;
    const value = await response.json();
    return value?.code === 0 && value?.data?.status === 'ok';
  } catch {
    return false;
  }
}

async function waitForReboot(context, label) {
  step(`${label}: waiting for updater shutdown and reboot`);
  let wentOffline = false;
  for (let attempt = 0; attempt < 48; attempt += 1) {
    if (!(await healthOnline(context))) {
      wentOffline = true;
      break;
    }
    await sleep(5000);
  }
  if (!wentOffline) step(`${label}: warning: HTTPS outage was too short to observe`);

  for (let attempt = 0; attempt < 180; attempt += 1) {
    if (await healthOnline(context)) return;
    await sleep(5000);
  }
  fail(`${label}: device did not return to HTTPS within 15 minutes`);
}

async function waitForBootGood(apiContext, csrfToken, label) {
  step(`${label}: waiting for automatic boot-good confirmation`);
  for (let attempt = 0; attempt < 18; attempt += 1) {
    const status = requireApiOk(
      await api(apiContext, csrfToken, '/api/system-update/status'),
      `${label} status`,
    );
    if (!status.pending) return;
    await sleep(10000);
  }
  fail(`${label}: update was not auto-confirmed`);
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

async function prepareCandidateStage(password) {
  step('candidate: validating local archive, signature, metadata, and manifest');
  for (const filename of [CANDIDATE_ARCHIVE, CANDIDATE_METADATA, CANDIDATE_SIGNATURE, UPDATE_PUBLIC_KEY, VERIFY_METADATA, SSHPASS]) {
    if (!fs.existsSync(filename)) fail(`candidate: required input is missing: ${filename}`);
  }
  if ((await sha256File(CANDIDATE_ARCHIVE)) !== CANDIDATE_SHA256) {
    fail('candidate: archive sha256 mismatch');
  }
  await runProcess(VERIFY_METADATA, [CANDIDATE_METADATA, CANDIDATE_SIGNATURE, UPDATE_PUBLIC_KEY]);
  const manifestRaw = await runProcess('/usr/bin/tar', ['-xOf', CANDIDATE_ARCHIVE, 'manifest.json']);
  const manifest = JSON.parse(manifestRaw.toString('utf8'));
  const latest = JSON.parse(fs.readFileSync(CANDIDATE_METADATA, 'utf8'));
  if (manifest.version !== CANDIDATE_VERSION || latest.version !== CANDIDATE_VERSION) {
    fail('candidate: version mismatch between expected version and metadata');
  }
  if (latest.sha256 !== CANDIDATE_SHA256) fail('candidate: metadata archive sha256 mismatch');
  const rootfs = manifest.raw_images?.find((image) => image.device === '/dev/mmcblk0p2');
  const boot = manifest.raw_images?.find((image) => image.device === '/dev/mmcblk0p1');
  if (rootfs?.size !== 1610612736 || boot?.size !== 16777216) {
    fail('candidate: unexpected raw partition image size');
  }

  const staged = {
    staged_at: Math.floor(Date.now() / 1000),
    latest,
    manifest,
  };
  const stagedPath = path.join(workDir, 'candidate-staged.json');
  fs.writeFileSync(stagedPath, `${JSON.stringify(staged, null, 2)}\n`, { mode: 0o600 });

  step('candidate: running SSH preflight after the control boot');
  const preflightText = await ssh(password, `set -eu
printf 'UID=%s\\n' "$(id -u)"
printf 'HOSTNAME=%s\\n' "$(hostname)"
printf 'KERNEL=%s\\n' "$(uname -r)"
printf 'ROOT_MOUNT=%s\\n' "$(awk '$2 == "/" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'BOOT_MOUNT=%s\\n' "$(awk '$2 == "/boot" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'DATA_MOUNT=%s\\n' "$(awk '$2 == "/data" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'DATA_FREE_KB=%s\\n' "$(df -Pk /data | awk 'NR == 2 { print $4 }')"
printf 'P1_SECTORS=%s\\n' "$(cat /sys/class/block/mmcblk0p1/size)"
printf 'P2_SECTORS=%s\\n' "$(cat /sys/class/block/mmcblk0p2/size)"
printf 'P3_SECTORS=%s\\n' "$(cat /sys/class/block/mmcblk0p3/size)"
printf 'SYSTEM_VERSION=%s\\n' "$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^" ]*\\)".*/\\1/p' /etc/kvm/system-version.json | head -n 1)"
printf 'APP_VERSION=%s\\n' "$(cat /kvmapp/version 2>/dev/null || true)"
printf 'BACKEND_PID=%s\\n' "$(pidof NanoKVM-Server 2>/dev/null || true)"
printf 'PUBLIC_KEY=%s\\n' "$([ -f /etc/kvm/system-update-signing.pub.pem ] && echo present || echo missing)"
printf 'BUSYBOX=%s\\n' "$([ -x /bin/busybox ] && echo present || echo missing)"
printf 'OPENSSL=%s\\n' "$(command -v openssl 2>/dev/null || true)"
MUSL_LOADER=''
for CANDIDATE in /lib/ld-musl-riscv64v0p7_xthead.so.1 /lib/ld-musl-riscv64xthead.so.1 /lib/ld-musl-riscv64.so.1; do
  if [ -f "$CANDIDATE" ]; then MUSL_LOADER="$CANDIDATE"; break; fi
done
printf 'MUSL_LOADER=%s\\n' "$MUSL_LOADER"
`);
  fs.writeFileSync(path.join(workDir, 'candidate-preflight.txt'), preflightText, { mode: 0o600 });
  const fields = parseFields(preflightText);
  if (fields.get('UID') !== '0') fail('candidate: SSH user is not root');
  if (!fields.get('HOSTNAME')) fail('candidate: hostname is empty');
  if (!fields.get('BOOT_MOUNT')?.startsWith('/dev/mmcblk0p1:')) fail('candidate: /boot is not mmcblk0p1');
  if (!fields.get('DATA_MOUNT')?.startsWith('/dev/mmcblk0p3:')) fail('candidate: /data is not mmcblk0p3');
  if (Number(fields.get('P1_SECTORS')) < 32768) fail('candidate: boot partition is too small');
  if (Number(fields.get('P2_SECTORS')) < 3145728) fail('candidate: rootfs partition is too small');
  if (Number(fields.get('DATA_FREE_KB')) * 1024 < manifest.required_free_bytes) fail('candidate: insufficient /data free space');
  if (fields.get('PUBLIC_KEY') !== 'present') fail('candidate: update public key is missing');
  if (fields.get('BUSYBOX') !== 'present' || !fields.get('MUSL_LOADER')) fail('candidate: raw updater runtime is incomplete');
  if (!fields.get('OPENSSL')) fail('candidate: openssl is unavailable');

  step(`candidate: preflight hostname=${fields.get('HOSTNAME')} system=${fields.get('SYSTEM_VERSION')} app=${fields.get('APP_VERSION')} kernel=${fields.get('KERNEL')}`);
  const mbr = await sshBinary(password, 'dd if=/dev/mmcblk0 bs=512 count=1 2>/dev/null');
  if (mbr.length !== 512) fail('candidate: MBR capture size mismatch');
  fs.writeFileSync(path.join(resultDir, 'mmcblk0-mbr.bin'), mbr, { mode: 0o600 });
  fs.writeFileSync(
    path.join(resultDir, 'mmcblk0-mbr.bin.sha256'),
    `${crypto.createHash('sha256').update(mbr).digest('hex')}  mmcblk0-mbr.bin\n`,
    { mode: 0o600 },
  );

  step('candidate: uploading signed archive and staged record to /data');
  const remoteArchive = `${REMOTE_STAGE}/${path.basename(CANDIDATE_ARCHIVE)}`;
  await ssh(password, `set -eu
mkdir -p '${REMOTE_STAGE}'
rm -rf '${REMOTE_STAGE}/extract'
rm -f '${REMOTE_STAGE}/progress.json' '${REMOTE_STAGE}/staged.json'
rm -f '${remoteArchive}.incoming' '${REMOTE_STAGE}/staged.json.incoming'
rm -f '${REMOTE_STAGE}/system-latest.json.incoming' '${REMOTE_STAGE}/system-latest.json.sig.incoming'
`);
  await scp(password, CANDIDATE_ARCHIVE, `${remoteArchive}.incoming`);
  await scp(password, stagedPath, `${REMOTE_STAGE}/staged.json.incoming`);
  await scp(password, CANDIDATE_METADATA, `${REMOTE_STAGE}/system-latest.json.incoming`);
  await scp(password, CANDIDATE_SIGNATURE, `${REMOTE_STAGE}/system-latest.json.sig.incoming`);
  await ssh(password, `set -eu
test "$(sha256sum '${remoteArchive}.incoming' | awk '{print $1}')" = '${CANDIDATE_SHA256}'
openssl dgst -sha256 -verify /etc/kvm/system-update-signing.pub.pem -signature '${REMOTE_STAGE}/system-latest.json.sig.incoming' '${REMOTE_STAGE}/system-latest.json.incoming' >/dev/null
mv '${remoteArchive}.incoming' '${remoteArchive}'
mv '${REMOTE_STAGE}/staged.json.incoming' '${REMOTE_STAGE}/staged.json'
mv '${REMOTE_STAGE}/system-latest.json.incoming' '${REMOTE_STAGE}/system-latest.json'
mv '${REMOTE_STAGE}/system-latest.json.sig.incoming' '${REMOTE_STAGE}/system-latest.json.sig'
chmod 0600 '${remoteArchive}' '${REMOTE_STAGE}/staged.json' '${REMOTE_STAGE}/system-latest.json' '${REMOTE_STAGE}/system-latest.json.sig'
sync
`);
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing destructive deployment without --confirm-device ${TARGET_IP}`);
  }
  const syncWebPassword = process.argv.includes('--sync-web-password');
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(workDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  step('validating the local copy of the published control release');
  if ((await sha256File(ARCHIVE)) !== EXPECTED_SHA256) fail('published control archive sha256 mismatch');

  let apiContext;
  let csrfToken;
  let rawEnabledByScript = false;
  try {
    apiContext = await createApiContext();
    step('logging in through encrypted direct HTTPS /api authentication');
    let sshVerified = false;
    try {
      csrfToken = await login(apiContext, password);
    } catch (error) {
      if (!syncWebPassword || error.apiCode !== -2) throw error;
      step('web credential mismatch confirmed; checking root SSH before approved synchronization');
      await ssh(password, 'true');
      sshVerified = true;
      step('synchronizing only the web admin bcrypt record through root SSH');
      await synchronizeWebAccount(password);
      csrfToken = await login(apiContext, password);
      step('web admin credential synchronization confirmed through /api');
    }
    if (!sshVerified) {
      step('checking root SSH through sshpass');
      await ssh(password, 'true');
    }

    const before = requireApiOk(
      await api(apiContext, csrfToken, '/api/system-update/version'),
      'system version',
    );
    const beforeSystem = before.current?.version ?? '';
    const beforeKernel = before.current?.kernelVersion ?? '';
    step(`before_system=${beforeSystem}`);
    step(`before_kernel=${beforeKernel}`);
    if (beforeSystem !== VERSION && beforeSystem !== CANDIDATE_VERSION) {
      step('control: checking the signed GitHub channel through /api');
      const check = requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/check'),
        'control update check',
      );
      if (check.latest?.version !== VERSION) fail('control: device did not select the expected published version');
      if (check.latest?.sha256 !== EXPECTED_SHA256) fail('control: selected metadata has an unexpected archive hash');
      if (check.updateAvailable !== true) fail('control: published update is not considered newer');

      step('control: enabling guarded raw updates');
      requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/raw-enabled', 'POST', { enabled: true }),
        'control enable raw updates',
      );
      rawEnabledByScript = true;

      step('control: downloading and verifying the GitHub raw through /api');
      const downloaded = requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/download', 'POST', {}),
        'control download system update',
      );
      if (downloaded.staged?.version !== VERSION) fail('control: device staged the wrong version');
      if (downloaded.staged?.destructive !== true) fail('control: staged update is not marked destructive');

      step('control: starting the published raw updater through /api');
      try {
        const installed = await api(apiContext, csrfToken, '/api/system-update/install', 'POST', {});
        requireApiOk(installed, 'control install system update');
      } catch (error) {
        step(`control: install request disconnected after updater start: ${error.name}`);
      }
      await waitForReboot(apiContext, 'control');

      step('control: HTTPS returned; checking preserved web account and versions');
      await sleep(10000);
      await apiContext.dispose();
      apiContext = await createApiContext();
      csrfToken = await login(apiContext, password);
      const after = requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/version'),
        'control post-reboot version',
      );
      if (after.current?.version !== VERSION) fail(`control: post-reboot version mismatch ${after.current?.version ?? ''}`);
      const app = requireApiOk(
        await api(apiContext, csrfToken, '/api/application/version'),
        'control post-reboot app',
      );
      if (app.current !== EXPECTED_APP_VERSION) fail(`control: post-reboot app mismatch ${app.current}`);
      await waitForBootGood(apiContext, csrfToken, 'control');

      step('control: disabling guarded raw updates after successful boot');
      requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/raw-enabled', 'POST', { enabled: false }),
        'control disable raw updates',
      );
      rawEnabledByScript = false;
      step(`control: SUCCESS system=${after.current.version} app=${app.current}`);
    } else if (beforeSystem === VERSION) {
      step('control: published raw is already installed; using it as the known-good baseline');
    } else {
      step('candidate: target version is already installed; skipping destructive writes and auditing current state');
    }

    let current = requireApiOk(
      await api(apiContext, csrfToken, '/api/system-update/version'),
      'pre-candidate system version',
    );
    if (current.current?.version !== CANDIDATE_VERSION) {
      await prepareCandidateStage(password);
      const stagedStatus = requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/status'),
        'candidate staged status',
      );
      if (stagedStatus.staged?.version !== CANDIDATE_VERSION) fail('candidate: backend did not accept staged version');
      if (stagedStatus.staged?.destructive !== true) fail('candidate: staged update is not marked destructive');

      step('candidate: enabling guarded raw updates through /api');
      requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/raw-enabled', 'POST', { enabled: true }),
        'candidate enable raw updates',
      );
      rawEnabledByScript = true;

      step('candidate: starting 0.3.0-raw.1 through the stock /api installer');
      try {
        const installed = await api(apiContext, csrfToken, '/api/system-update/install', 'POST', {});
        requireApiOk(installed, 'candidate install system update');
      } catch (error) {
        step(`candidate: install request disconnected after updater start: ${error.name}`);
      }
      await waitForReboot(apiContext, 'candidate');

      step('candidate: HTTPS returned; checking preserved web account and versions');
      await sleep(10000);
      await apiContext.dispose();
      apiContext = await createApiContext();
      csrfToken = await login(apiContext, password);
      current = requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/version'),
        'candidate post-reboot version',
      );
      if (current.current?.version !== CANDIDATE_VERSION) {
        fail(`candidate: post-reboot version mismatch ${current.current?.version ?? ''}`);
      }
      const candidateApp = requireApiOk(
        await api(apiContext, csrfToken, '/api/application/version'),
        'candidate post-reboot app',
      );
      if (candidateApp.current !== CANDIDATE_APP_VERSION) {
        fail(`candidate: post-reboot app mismatch ${candidateApp.current}`);
      }
      await waitForBootGood(apiContext, csrfToken, 'candidate');

      step('candidate: disabling guarded raw updates after successful boot');
      requireApiOk(
        await api(apiContext, csrfToken, '/api/system-update/raw-enabled', 'POST', { enabled: false }),
        'candidate disable raw updates',
      );
      rawEnabledByScript = false;
    }

    step('candidate: running final SSH and /api acceptance checks');
    const postflightText = await ssh(password, `set -eu
printf 'SYSTEM_VERSION=%s\\n' "$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^" ]*\\)".*/\\1/p' /etc/kvm/system-version.json | head -n 1)"
printf 'APP_VERSION=%s\\n' "$(cat /kvmapp/version)"
printf 'KERNEL=%s\\n' "$(uname -r)"
printf 'OS_PRETTY=%s\\n' "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"')"
printf 'ROOT_MOUNT=%s\\n' "$(awk '$2 == "/" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'BOOT_MOUNT=%s\\n' "$(awk '$2 == "/boot" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'DATA_MOUNT=%s\\n' "$(awk '$2 == "/data" { print $1 ":" $3 ":" $4 }' /proc/mounts)"
printf 'BACKEND_PID=%s\\n' "$(pidof NanoKVM-Server 2>/dev/null || true)"
printf 'KVM_SYSTEM_PID=%s\\n' "$(pidof kvm_system 2>/dev/null || true)"
printf 'WEB_INDEX=%s\\n' "$([ -f /kvmapp/server/web/index.html ] && echo present || echo missing)"
printf 'RESTORE_DONE=%s\\n' "$([ -f /data/.hardened-kvmcache/system-update/root-restore-done ] && echo present || echo missing)"
printf 'RAW_MARKER=%s\\n' "$([ -f /data/hardened-system-raw-update-pending.json ] && echo present || echo cleared)"
printf 'BOOT_GOOD=%s\\n' "$([ -f /etc/kvm/system-update-boot-good.json ] && echo present || echo missing)"
`);
    fs.writeFileSync(path.join(workDir, 'candidate-postflight.txt'), postflightText, { mode: 0o600 });
    const post = parseFields(postflightText);
    if (post.get('SYSTEM_VERSION') !== CANDIDATE_VERSION) fail('candidate: final system version mismatch');
    if (post.get('APP_VERSION') !== CANDIDATE_APP_VERSION) fail('candidate: final app version mismatch');
    if (!post.get('OS_PRETTY')?.includes('Buildroot 2026.05.1')) fail(`candidate: unexpected userspace ${post.get('OS_PRETTY') ?? ''}`);
    if (!post.get('BACKEND_PID') || !post.get('KVM_SYSTEM_PID')) fail('candidate: required runtime process is missing');
    if (post.get('WEB_INDEX') !== 'present' || post.get('RESTORE_DONE') !== 'present') {
      fail('candidate: web root or preserved configuration restore evidence is missing');
    }
    if (post.get('RAW_MARKER') !== 'cleared' || post.get('BOOT_GOOD') !== 'present') {
      fail('candidate: boot-good state is incomplete');
    }
    const rawState = requireApiOk(
      await api(apiContext, csrfToken, '/api/system-update/raw-enabled'),
      'candidate raw flag status',
    );
    if (rawState.enabled !== false) fail('candidate: raw updates remained enabled');
    requireApiOk(await api(apiContext, csrfToken, '/api/vm/hdmi'), 'candidate HDMI API');

    step(`candidate: after_system=${post.get('SYSTEM_VERSION')}`);
    step(`candidate: after_app=${post.get('APP_VERSION')}`);
    step(`candidate: after_kernel=${post.get('KERNEL')}`);
    step(`candidate: userspace=${post.get('OS_PRETTY')}`);
    step(`candidate: root_mount=${post.get('ROOT_MOUNT')}`);
    step(`candidate: boot_mount=${post.get('BOOT_MOUNT')}`);
    step(`candidate: data_mount=${post.get('DATA_MOUNT')}`);
    step('SUCCESS: latest Buildroot raw installed and passed basic boot acceptance');
  } finally {
    if (rawEnabledByScript && apiContext && csrfToken) {
      try {
        await api(apiContext, csrfToken, '/api/system-update/raw-enabled', 'POST', { enabled: false });
      } catch {}
    }
    if (apiContext) await apiContext.dispose();
  }
}

main().catch((error) => {
  try {
    step(`FAILED: ${error.message}`);
  } catch {}
  process.exitCode = 1;
});
