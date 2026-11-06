#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `backend-diagnostic-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');
const knownHostsPath = path.join(resultDir, 'known_hosts');

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

async function main() {
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  const password = await readSecret();
  if (!password) throw new Error('secret stdin was empty');
  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    throw new Error('unexpected SSH fingerprint');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });

  const remote = `set -u
printf 'SYSTEM_VERSION=%s\\n' "$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^" ]*\\)".*/\\1/p' /etc/kvm/system-version.json | head -n 1)"
printf 'APP_VERSION=%s\\n' "$(cat /kvmapp/version 2>/dev/null || true)"
printf 'BACKEND_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/NanoKVM-Server 2>/dev/null | awk '{print $1}')"
printf 'BACKEND_RUNTIME_SHA=%s\\n' "$(sha256sum /tmp/server/NanoKVM-Server 2>/dev/null | awk '{print $1}')"
printf 'SERVER_PID_FILE=%s\\n' "$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
printf 'SERVER_PID_ALIVE=%s\\n' "$([ -r /tmp/nanokvm-server.pid ] && kill -0 "$(cat /tmp/nanokvm-server.pid)" 2>/dev/null && echo yes || echo no)"
printf 'KVM_PID_FILE=%s\\n' "$(cat /tmp/kvm-system.pid 2>/dev/null || true)"
printf 'KVM_PID_FILE_ALIVE=%s\\n' "$([ -r /tmp/kvm-system.pid ] && kill -0 "$(cat /tmp/kvm-system.pid)" 2>/dev/null && echo yes || echo no)"
printf 'CONFIG_PROTO=%s\\n' "$(awk -F: '/^[[:space:]]*proto:/ { value=$2; gsub(/[[:space:]\"]/, "", value); print value; exit }' /etc/kvm/server.yaml 2>/dev/null || true)"
printf 'CONFIG_CERT_CRT=%s\\n' "$(awk -F: '/^[[:space:]]*crt:/ { value=$2; gsub(/^[[:space:]\"]+|[[:space:]\"]+$/, "", value); print value; exit }' /etc/kvm/server.yaml 2>/dev/null || true)"
printf 'CONFIG_CERT_KEY=%s\\n' "$(awk -F: '/^[[:space:]]*key:/ { value=$2; gsub(/^[[:space:]\"]+|[[:space:]\"]+$/, "", value); print value; exit }' /etc/kvm/server.yaml 2>/dev/null || true)"
printf 'ETC_CERT=%s\\n' "$([ -s /etc/kvm/server.crt ] && echo present || echo missing)"
printf 'ETC_KEY=%s\\n' "$([ -s /etc/kvm/server.key ] && echo present || echo missing)"
printf 'KVMAPP_CERT=%s\\n' "$([ -s /kvmapp/server/server.crt ] && echo present || echo missing)"
printf 'KVMAPP_KEY=%s\\n' "$([ -s /kvmapp/server/server.key ] && echo present || echo missing)"
printf 'PORT80=%s\\n' "$(awk '$2 ~ /:0050$/ && $4 == "0A" { print "listen"; exit }' /proc/net/tcp /proc/net/tcp6 2>/dev/null)"
printf 'PORT443=%s\\n' "$(awk '$2 ~ /:01BB$/ && $4 == "0A" { print "listen"; exit }' /proc/net/tcp /proc/net/tcp6 2>/dev/null)"
printf 'PROCESS_CMDLINES_BEGIN\\n'
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in
    /lib/ld-musl-riscv64xthead.so.1*'/tmp/server/NanoKVM-Server'*) printf '%s %s\\n' "\${PROC##*/}" "$CMD" ;;
    /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) printf '%s %s\\n' "\${PROC##*/}" "$CMD" ;;
  esac
done
printf 'PROCESS_CMDLINES_END\\n'
printf 'WATCHDOG_LOG_BEGIN\\n'
tail -n 80 /run/nanokvm-watchdog.log 2>/dev/null || true
printf 'WATCHDOG_LOG_END\\n'
printf 'SERVER_LOG_BEGIN\\n'
tail -n 120 /run/nanokvm-native.log 2>/dev/null || true
printf 'SERVER_LOG_END\\n'
`;
  const output = await run(
    SSHPASS,
    [
      '-d', '3', 'ssh', '-o', 'ConnectTimeout=10', '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsPath}`,
      `root@${TARGET_IP}`, remote,
    ],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
  fs.writeFileSync(reportPath, output, { mode: 0o600 });
}

main().catch((error) => {
  try { fs.appendFileSync(reportPath, `FAILED=${error.message}\n`, { mode: 0o600 }); } catch {}
  process.exitCode = 1;
});
