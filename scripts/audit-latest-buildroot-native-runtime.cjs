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
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `native-audit-${TARGET_IP}-${runId}`);
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
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    throw new Error(`refusing native audit without --confirm-device ${TARGET_IP}`);
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

  const command = `set -u
LIBPATH=/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd
BACKEND_PID="$(cat /tmp/nanokvm-server.pid)"
kill -0 "$BACKEND_PID"
KVM_PID=''
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in
    /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_PID="\${PROC##*/}"; break ;;
  esac
done

printf 'BACKEND_PID=%s\\n' "$BACKEND_PID"
printf 'KVM_SYSTEM_PID=%s\\n' "$KVM_PID"
printf 'BACKEND_THREADS=%s\\n' "$(find "/proc/$BACKEND_PID/task" -mindepth 1 -maxdepth 1 | wc -l)"
if [ -n "$KVM_PID" ]; then KVM_THREADS="$(find "/proc/$KVM_PID/task" -mindepth 1 -maxdepth 1 | wc -l)"; else KVM_THREADS=0; fi
printf 'KVM_SYSTEM_THREADS=%s\\n' "$KVM_THREADS"
printf 'BACKEND_CMDLINE=%s\\n' "$(tr '\\0' ' ' < "/proc/$BACKEND_PID/cmdline")"
if [ -n "$KVM_PID" ]; then KVM_CMDLINE="$(tr '\\0' ' ' < "/proc/$KVM_PID/cmdline")"; else KVM_CMDLINE=''; fi
printf 'KVM_SYSTEM_CMDLINE=%s\\n' "$KVM_CMDLINE"

printf 'BACKEND_LIST_BEGIN\\n'
/lib/ld-musl-riscv64xthead.so.1 --library-path "$LIBPATH" --list /kvmapp/server/NanoKVM-Server >/tmp/hardened-backend-list.txt 2>&1
BACKEND_LIST_RC=$?
cat /tmp/hardened-backend-list.txt
rm -f /tmp/hardened-backend-list.txt
printf 'BACKEND_LIST_END\\n'
printf 'BACKEND_LIST_RC=%s\\n' "$BACKEND_LIST_RC"
printf 'KVM_SYSTEM_LIST_BEGIN\\n'
/lib/ld-musl-riscv64v0p7_xthead.so.1 --library-path "$LIBPATH" --list /tmp/kvm_system/kvm_system >/tmp/hardened-kvm-system-list.txt 2>&1
KVM_SYSTEM_LIST_RC=$?
cat /tmp/hardened-kvm-system-list.txt
rm -f /tmp/hardened-kvm-system-list.txt
printf 'KVM_SYSTEM_LIST_END\\n'
printf 'KVM_SYSTEM_LIST_RC=%s\\n' "$KVM_SYSTEM_LIST_RC"

printf 'BACKEND_MAPS_BEGIN\\n'
awk '$6 ~ /^\\// { print $6 }' "/proc/$BACKEND_PID/maps" | sort -u | grep -E '/(lib(std|gcc|gomp|atomic|z)|libopencv|libprotobuf|libkvm|libc\\.so|ld-musl|mnt/system)' || true
printf 'BACKEND_MAPS_END\\n'
printf 'KVM_SYSTEM_MAPS_BEGIN\\n'
if [ -n "$KVM_PID" ]; then
  awk '$6 ~ /^\\// { print $6 }' "/proc/$KVM_PID/maps" | sort -u | grep -E '/(lib(std|gcc|gomp|atomic|z)|libopencv|libprotobuf|libkvm|libc\\.so|ld-musl|mnt/system)' || true
fi
printf 'KVM_SYSTEM_MAPS_END\\n'

require_private_map() {
  logical="$1"
  shift
  for name in "$@"; do
    grep -q "/kvmapp/server/dl_lib/$name" "/proc/$BACKEND_PID/maps" && return 0
  done
  printf 'MISSING_PRIVATE_MAP=%s\\n' "$logical"
}
require_private_map libstdc++ libstdc++.so.6.0.28 libstdc++.so.6
require_private_map libgcc libgcc_s.so.1
require_private_map libgomp libgomp.so.1.0.0 libgomp.so.1
require_private_map libatomic libatomic.so.1.2.0 libatomic.so.1
if ! grep -q '/usr/lib/libz.so.1.3.2' "/proc/$BACKEND_PID/maps"; then
  printf 'MISSING_SYSTEM_MAP=libz\n'
fi
if grep -q '/kvmapp/server/dl_lib/libz.so' "/proc/$BACKEND_PID/maps"; then
  printf 'PRIVATE_ZLIB_MAP=present\n'
fi
if grep -Eiq 'not found|Error loading shared library' /tmp/nanokvm-server.log; then
  printf 'SERVER_LOADER_ERRORS=present\\n'
else
  printf 'SERVER_LOADER_ERRORS=none\\n'
fi
ALERT_PATTERN='oops|panic|segfault|BUG:|module_put|fail to allocate ion|Invalid buffer|already inited|Unknown symbol|disagrees about version|invalid module format|VPSS.*(fail|error)|VENC.*(fail|error)'
printf 'DMESG_ALERTS=%s\\n' "$(dmesg 2>/dev/null | grep -Eic "$ALERT_PATTERN" || true)"
printf 'DMESG_ALERT_LINES_BEGIN\\n'
dmesg 2>/dev/null | grep -Ei "$ALERT_PATTERN" | tail -n 120 || true
printf 'DMESG_ALERT_LINES_END\\n'
printf 'KVM_SYSTEM_LOG_BEGIN\\n'
tail -n 120 /tmp/kvm_system.log 2>/dev/null || true
printf 'KVM_SYSTEM_LOG_END\\n'
`;
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
  const text = output.toString('utf8');
  fs.writeFileSync(reportPath, text, { mode: 0o600 });
  if (text.includes('MISSING_PRIVATE_MAP=')) throw new Error('native private map closure is incomplete');
  if (text.includes('MISSING_SYSTEM_MAP=') || text.includes('PRIVATE_ZLIB_MAP=present')) {
    throw new Error('backend is not using the Buildroot system zlib');
  }
  if (!text.includes('SERVER_LOADER_ERRORS=none')) throw new Error('server loader errors are present');
  if (!text.includes('DMESG_ALERTS=0')) throw new Error('kernel alerts detected');
  if (!/^KVM_SYSTEM_PID=[0-9]+$/m.test(text)) throw new Error('kvm_system process is not running');
  if (!text.includes('BACKEND_LIST_RC=0') || !text.includes('KVM_SYSTEM_LIST_RC=0')) {
    throw new Error('one or more loader --list probes failed');
  }
}

main().catch((error) => {
  try { fs.appendFileSync(reportPath, `FAILED=${error.message}\n`, { mode: 0o600 }); } catch {}
  process.exitCode = 1;
});
