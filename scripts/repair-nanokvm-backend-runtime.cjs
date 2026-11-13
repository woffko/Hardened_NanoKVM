#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const EXPECTED_BACKEND = '80c23266d899d0cd6b243da02c79775d08772f6508c40ff9465d35aed78d83c4';
const ARCHIVE = path.join(ROOT, 'build/latestbuildroot/runtime-repair/dl-lib-complete.tar.gz');
const ARCHIVE_SHA256 = '27855c153164d54ab68100ef8b52a468fc8146ef658e931c8f5623b40e09449f';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `runtime-repair-${TARGET_IP}-${runId}`);
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

function commonSshOptions() {
  return [
    '-o', 'ConnectTimeout=10', '-o', 'PreferredAuthentications=password,keyboard-interactive',
    '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
  ];
}

async function main() {
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(ARCHIVE)) throw new Error('runtime repair archive is missing');
  const password = await readSecret();
  if (!password) throw new Error('secret stdin was empty');
  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    throw new Error('unexpected SSH fingerprint');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });

  const remoteArchive = '/tmp/hardened-dl-lib-repair.tar.gz';
  await run(
    SSHPASS,
    ['-d', '3', 'scp', '-O', ...commonSshOptions(), ARCHIVE, `root@${TARGET_IP}:${remoteArchive}`],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );

  const command = `set -eu
test "$(sha256sum '${remoteArchive}' | awk '{print $1}')" = '${ARCHIVE_SHA256}'
mkdir -p /kvmapp/server/dl_lib
gzip -dc '${remoteArchive}' | tar -C /kvmapp/server/dl_lib -xf -
rm -f '${remoteArchive}'
# Runtime repair must not import TLS identity from untrusted legacy p3 state.
# Missing/invalid TLS identity needs a separate reviewed recovery operation.
test "$(sha256sum /kvmapp/server/NanoKVM-Server | awk '{print $1}')" = '${EXPECTED_BACKEND}'
test -e /kvmapp/server/dl_lib/libopencv_video.so.409
test -e /kvmapp/server/dl_lib/libprotobuf.so.32
/etc/init.d/S95nanokvm restart
sleep 8
PID="$(cat /tmp/nanokvm-server.pid 2>/dev/null || true)"
test -n "$PID"
kill -0 "$PID"
printf 'BACKEND_DISK_SHA=%s\\n' "$(sha256sum /kvmapp/server/NanoKVM-Server | awk '{print $1}')"
printf 'BACKEND_RUNTIME_SHA=%s\\n' "$(sha256sum /tmp/server/NanoKVM-Server | awk '{print $1}')"
printf 'SERVER_PID=%s\\n' "$PID"
printf 'SERVER_PID_ALIVE=yes\\n'
printf 'CERT=%s\\n' "$([ -s /etc/kvm/server.crt ] && echo present || echo missing)"
printf 'KEY=%s\\n' "$([ -s /etc/kvm/server.key ] && echo present || echo missing)"
`;
  const output = await run(
    SSHPASS,
    ['-d', '3', 'ssh', ...commonSshOptions(), `root@${TARGET_IP}`, command],
    undefined,
    Buffer.from(`${password}\n`, 'utf8'),
  );
  fs.writeFileSync(reportPath, output, { mode: 0o600 });
}

main().catch((error) => {
  try { fs.appendFileSync(reportPath, `FAILED=${error.message}\n`, { mode: 0o600 }); } catch {}
  process.exitCode = 1;
});
