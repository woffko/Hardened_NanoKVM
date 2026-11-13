#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const TEST_LABEL = process.env.TEST_LABEL || 'raw10';
const EXPECTED_ENV_NAMES = [
  'EXPECTED_SYSTEM_VERSION',
  'EXPECTED_APP_VERSION',
  'EXPECTED_HOSTNAME',
  'EXPECTED_BACKEND_SHA256',
  'EXPECTED_KVM_SYSTEM_SHA256',
  'EXPECTED_LIBKVM_SHA256',
  'EXPECTED_LIBKVM_MMF_SHA256',
  'EXPECTED_S30ETH_SHA256',
  'EXPECTED_SOPH_VCODEC_SHA256',
  'EXPECTED_SOPH_JPEG_SHA256',
  'EXPECTED_SOPH_VC_DRIVER_SHA256',
];
const expectedEnvironment = Object.fromEntries(
  EXPECTED_ENV_NAMES.flatMap((name) => (
    process.env[name] === undefined ? [] : [[name, process.env[name]]]
  )),
);
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(
  ROOT,
  'build/latestbuildroot/device-tests',
  `${TEST_LABEL}-regression-suite-${TARGET_IP}-${runId}`,
);
const reportPath = path.join(resultDir, 'report.txt');

const tests = [
  ['core-before', 'verify-latest-buildroot-device.cjs'],
  ['network', 'audit-latest-buildroot-network.cjs'],
  ['remote-syslog', 'test-latest-buildroot-remote-syslog.cjs'],
  ['native-runtime', 'audit-latest-buildroot-native-runtime.cjs'],
  ['browser', 'smoke-latest-buildroot-browser.cjs'],
  ['h264-direct-resume', 'test-latest-buildroot-h264-direct-resume.cjs'],
  ['video-streams', 'soak-latest-buildroot-streams.cjs'],
  ['usb-safe', 'test-latest-buildroot-usb-safe.cjs'],
  ['peripherals-read-only', 'audit-latest-buildroot-peripherals.cjs'],
  ['watchdog-recovery', 'test-latest-buildroot-watchdog.cjs'],
  ['core-after-watchdog', 'verify-latest-buildroot-device.cjs'],
  ['five-reboots', 'soak-latest-buildroot-reboots.cjs'],
  ['core-final', 'verify-latest-buildroot-device.cjs'],
];

function step(message) {
  fs.appendFileSync(reportPath, `${new Date().toISOString()} ${message}\n`, { mode: 0o600 });
}

async function readSecret() {
  let input = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) input += chunk;
  return input.replace(/\r?\n$/, '');
}

async function runTest(name, script, password) {
  const scriptPath = path.join(ROOT, 'scripts', script);
  if (!fs.existsSync(scriptPath)) throw new Error(`${name}: missing script ${script}`);
  step(`${name}=started`);
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, '--confirm-device', TARGET_IP], {
      cwd: ROOT,
      env: {
        HOME: '/home/w0w',
        USER: 'w0w',
        LANG: 'C',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        ...expectedEnvironment,
      },
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    let stderrBytes = 0;
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`${name}: ${script} exited ${code}; stderr_bytes=${stderrBytes}`));
        return;
      }
      resolve();
    });
    child.stdin.end(`${password}\n`);
  });
  step(`${name}=passed`);
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    throw new Error(`refusing regression suite without --confirm-device ${TARGET_IP}`);
  }
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(TEST_LABEL)) {
    throw new Error('TEST_LABEL must be a short filesystem-safe identifier');
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) throw new Error('secret stdin was empty');

  for (const [name, script] of tests) {
    await runTest(name, script, password);
  }
  step(`SUCCESS: ${TEST_LABEL} automated device regression suite passed`);
}

main().catch((error) => {
  try {
    step(`FAILED: ${error.message}`);
  } catch {}
  process.exitCode = 1;
});
