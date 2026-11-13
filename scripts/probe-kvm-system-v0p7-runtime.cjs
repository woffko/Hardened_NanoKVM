#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const TOOLCHAIN_LIB = path.join(
  '/home/w0w/MaixCDK/dl/extracted/toolchains/maixcam/host-tools/gcc',
  'riscv64-linux-musl-x86_64/riscv64-unknown-linux-musl/lib64v0p7_xthead/lp64d',
);
const LIBSTDCXX = path.join(TOOLCHAIN_LIB, 'libstdc++.so.6.0.28');
const LIBGCC = path.join(TOOLCHAIN_LIB, 'libgcc_s.so.1');
const CLEAN_HELPER = path.join(ROOT, 'support/sg2002/kvm_system/build/kvm_system');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(
  ROOT,
  'build/latestbuildroot/device-tests',
  `kvm-system-v0p7-probe-${TARGET_IP}-${runId}`,
);
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
      env: {
        HOME: '/home/w0w',
        USER: 'w0w',
        LANG: 'C',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      },
      stdio: secret === undefined ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe', 'pipe'],
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
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}

function sshArgs(knownHostsPath, remoteCommand) {
  return [
    '-d', '3', 'ssh',
    '-o', 'ConnectTimeout=10',
    '-o', 'PreferredAuthentications=password,keyboard-interactive',
    '-o', 'PubkeyAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    `root@${TARGET_IP}`,
    remoteCommand,
  ];
}

function scpArgs(knownHostsPath, source, destination) {
  return [
    '-d', '3', 'scp',
    '-o', 'ConnectTimeout=10',
    '-o', 'PreferredAuthentications=password,keyboard-interactive',
    '-o', 'PubkeyAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    source,
    `root@${TARGET_IP}:${destination}`,
  ];
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    throw new Error(`refusing v0p7 probe without --confirm-device ${TARGET_IP}`);
  }
  for (const file of [SSHPASS, LIBSTDCXX, LIBGCC, CLEAN_HELPER]) {
    if (!fs.existsSync(file)) throw new Error(`missing required local file: ${file}`);
  }

  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  const password = await readSecret();
  if (!password) throw new Error('secret stdin was empty');

  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fps = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fps.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    throw new Error('unexpected SSH fingerprint');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });

  const secret = Buffer.from(`${password}\n`, 'utf8');
  await run(SSHPASS, scpArgs(knownHostsPath, LIBSTDCXX, '/tmp/hardened-v0p7-libstdc++.so.6.0.28'), undefined, secret);
  await run(SSHPASS, scpArgs(knownHostsPath, LIBGCC, '/tmp/hardened-v0p7-libgcc_s.so.1'), undefined, secret);
  await run(SSHPASS, scpArgs(knownHostsPath, CLEAN_HELPER, '/tmp/hardened-v0p7-kvm_system'), undefined, secret);

  const remoteCommand = String.raw`set -u
PROBE=/tmp/hardened-kvm-v0p7-probe
LOADER=/lib/ld-musl-riscv64v0p7_xthead.so.1
INSTALLED_HELPER=/tmp/kvm_system/kvm_system
HELPER=/tmp/hardened-v0p7-kvm_system
CURRENT=/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd
chmod 0755 "$HELPER"
rm -rf "$PROBE"
mkdir -p "$PROBE/dl_lib"
mv /tmp/hardened-v0p7-libstdc++.so.6.0.28 "$PROBE/dl_lib/libstdc++.so.6.0.28"
mv /tmp/hardened-v0p7-libgcc_s.so.1 "$PROBE/dl_lib/libgcc_s.so.1"
ln -s libstdc++.so.6.0.28 "$PROBE/dl_lib/libstdc++.so.6"
cp "$HELPER" "$PROBE/kvm_system"
chmod 0755 "$PROBE/kvm_system"

probe_list() {
  label="$1"
  shift
  output="$PROBE/$label.txt"
  "$@" >"$output" 2>&1
  rc=$?
  printf '%s_BEGIN\n' "$label"
  sed -n '1,80p' "$output"
  printf '%s_END\n' "$label"
  printf '%s_RC=%s\n' "$label" "$rc"
}

printf 'INSTALLED_HELPER_SHA256=%s\n' "$(sha256sum "$INSTALLED_HELPER" | awk '{print $1}')"
printf 'CLEAN_HELPER_SHA256=%s\n' "$(sha256sum "$HELPER" | awk '{print $1}')"
printf 'V0P7_LIBSTDCXX_SHA256=%s\n' "$(sha256sum "$PROBE/dl_lib/libstdc++.so.6.0.28" | awk '{print $1}')"
printf 'V0P7_LIBGCC_SHA256=%s\n' "$(sha256sum "$PROBE/dl_lib/libgcc_s.so.1" | awk '{print $1}')"
probe_list INSTALLED_CURRENT "$LOADER" --library-path "$CURRENT" --list "$INSTALLED_HELPER"
probe_list CLEAN_CURRENT "$LOADER" --library-path "$CURRENT" --list "$HELPER"
probe_list DEDICATED_NO_LIBC "$LOADER" --library-path "$PROBE/dl_lib" --list "$PROBE/kvm_system"
ln -s "$LOADER" "$PROBE/dl_lib/libc.so"
probe_list DEDICATED_SELF_LIBC "$LOADER" --library-path "$PROBE/dl_lib" --list "$PROBE/kvm_system"

SMOKE_LOG="$PROBE/smoke.log"
"$LOADER" --library-path "$PROBE/dl_lib" "$PROBE/kvm_system" >"$SMOKE_LOG" 2>&1 &
SMOKE_PID=$!
sleep 3
if kill -0 "$SMOKE_PID" 2>/dev/null; then
  printf 'SMOKE_ALIVE_AFTER_3S=yes\n'
  kill "$SMOKE_PID" 2>/dev/null || true
  sleep 1
  kill -0 "$SMOKE_PID" 2>/dev/null && kill -9 "$SMOKE_PID" 2>/dev/null || true
else
  printf 'SMOKE_ALIVE_AFTER_3S=no\n'
fi
wait "$SMOKE_PID" 2>/dev/null || true
printf 'SMOKE_LOG_BEGIN\n'
sed -n '1,120p' "$SMOKE_LOG"
printf 'SMOKE_LOG_END\n'
printf 'DMESG_ALERTS=%s\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:' || true)"
rm -rf "$PROBE" "$HELPER"
`;
  const output = await run(SSHPASS, sshArgs(knownHostsPath, remoteCommand), undefined, secret);
  const text = output.toString('utf8');
  fs.writeFileSync(reportPath, text, { mode: 0o600 });
  if (!text.includes('CLEAN_CURRENT_RC=0')) {
    throw new Error('clean kvm_system did not resolve with the current vendor runtime closure');
  }
  if (!text.includes('DEDICATED_SELF_LIBC_RC=0')) {
    throw new Error('clean kvm_system did not resolve with the dedicated v0p7 closure');
  }
  if (!text.includes('SMOKE_ALIVE_AFTER_3S=yes')) {
    throw new Error('kvm_system did not stay alive with dedicated v0p7 closure');
  }
  if (!text.includes('DMESG_ALERTS=0')) throw new Error('kernel alerts detected');
}

main().catch((error) => {
  try { fs.appendFileSync(reportPath, `FAILED=${error.message}\n`, { mode: 0o600 }); } catch {}
  process.exitCode = 1;
});
