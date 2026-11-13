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
const REMOTE_HOST = '10.0.77.177';
const REMOTE_PORT = 514;
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const configure = process.argv.includes('--configure');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `remote-syslog-${configure ? 'configure' : 'verify'}-${TARGET_IP}-${runId}`);
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

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing remote syslog test without --confirm-device ${TARGET_IP}`);
  }
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

  const context = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 30000 });
  try {
    const loginResponse = await context.post('/api/auth/login', {
      data: { username: 'admin', password: encryptPassword(password) },
    });
    const login = await loginResponse.json();
    if (!loginResponse.ok() || login?.code !== 0 || !login?.data?.csrfToken) fail('API login failed');
    const csrfToken = login.data.csrfToken;

    let configResponse = await context.get('/api/system-log/config');
    let config = await configResponse.json();
    if (!configResponse.ok() || config?.code !== 0 || !config?.data?.config) fail('system log config API failed');
    if (configure) {
      const next = {
        ...config.data.config,
        remoteEnabled: true,
        remoteHost: REMOTE_HOST,
        remotePort: REMOTE_PORT,
      };
      configResponse = await context.post('/api/system-log/config', {
        headers: { 'x-csrf-token': csrfToken },
        data: next,
      });
      config = await configResponse.json();
      if (!configResponse.ok() || config?.code !== 0 || !config?.data?.config) fail('system log configuration failed');
      const testResponse = await context.post('/api/system-log/test', {
        headers: { 'x-csrf-token': csrfToken },
      });
      const test = await testResponse.json();
      if (!testResponse.ok() || test?.code !== 0) fail('remote syslog test message failed');
      step('configuration_applied=yes');
    }

    const active = config.data.config;
    if (active.remoteEnabled !== true || active.remoteHost !== REMOTE_HOST || active.remotePort !== REMOTE_PORT) {
      fail('remote syslog API configuration mismatch');
    }

    const state = (await run(
      SSHPASS,
      [
        '-d', '3', 'ssh', '-o', 'ConnectTimeout=10', '-o', 'PreferredAuthentications=password,keyboard-interactive',
        '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsPath}`,
        `root@${TARGET_IP}`,
        `set -eu
printf 'CONFIG_FILE=%s\\n' "$([ -s /etc/kvm/syslog.json ] && echo present || echo missing)"
printf 'SYSLOG_DEFAULT=%s\\n' "$(grep -Fq -- '-R ${REMOTE_HOST}:${REMOTE_PORT}' /etc/default/syslogd && grep -Fq -- '-L' /etc/default/syslogd && echo configured || echo missing)"
printf 'KLOG_DEFAULT=%s\\n' "$([ -s /etc/default/klogd ] && echo present || echo missing)"
SYSLOG_PID="$(cat /var/run/syslogd.pid 2>/dev/null || true)"
printf 'SYSLOG_PID=%s\\n' "$SYSLOG_PID"
printf 'SYSLOG_RUNNING=%s\\n' "$([ -n "$SYSLOG_PID" ] && kill -0 "$SYSLOG_PID" 2>/dev/null && echo yes || echo no)"
printf 'SYSLOG_CMDLINE=%s\\n' "$(tr '\\0' ' ' < "/proc/$SYSLOG_PID/cmdline" 2>/dev/null || true)"
printf 'LOCAL_LOG=%s\\n' "$([ -s /run/hardened-syslog/messages ] && echo present || echo missing)"
`,
      ],
      undefined,
      Buffer.from(`${password}\n`, 'utf8'),
    )).toString('utf8');
    fs.writeFileSync(path.join(resultDir, 'ssh-state.txt'), state, { mode: 0o600 });
    fs.writeFileSync(path.join(resultDir, 'api-config.json'), `${JSON.stringify(config.data, null, 2)}\n`, { mode: 0o600 });
    for (const expected of [
      'CONFIG_FILE=present', 'SYSLOG_DEFAULT=configured', 'KLOG_DEFAULT=present',
      'SYSLOG_RUNNING=yes', 'LOCAL_LOG=present', `-R ${REMOTE_HOST}:${REMOTE_PORT}`, '-L',
    ]) {
      if (!state.includes(expected)) fail(`remote syslog runtime missing ${expected}`);
    }
    step(`remote=${REMOTE_HOST}:${REMOTE_PORT}/udp`);
    step('local_copy=present');
    step(`SUCCESS: remote syslog ${configure ? 'configured and verified' : 'configuration survived and is active'}`);
  } finally {
    await context.dispose();
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
