#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { DeviceTestFailure, reportableFailure } = require('./lib/device-test-errors.cjs');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = process.env.TARGET_IP || '';
const CYCLES = Number(process.env.REBOOT_CYCLES || '10');
// SSHPASS is conventionally a password, never an executable-path override.
const SSHPASS_BIN = process.env.SSHPASS_BIN || path.join(
  ROOT,
  'build/host-deps/sshpass/usr/bin/sshpass',
);
const RESULT_DIR = process.env.DEVICE_TEST_RESULT_DIR || path.join(
  ROOT,
  'build/latestbuildroot/device-tests',
  `phase3-dmesg-reboots-${TARGET_IP}`,
);
const REPORT = path.join(RESULT_DIR, 'report.txt');
const KNOWN_HOSTS = path.join(RESULT_DIR, 'known_hosts');
const DEVICE_SCRIPT = path.resolve(
  ROOT,
  process.env.DEVICE_VERIFIER_SCRIPT || 'scripts/verify-kernel-dmesg-restriction-device.sh',
);
const EXPECTED_SUCCESS = process.env.DEVICE_VERIFIER_SUCCESS
  || 'SUCCESS: Phase 3 dmesg restriction device gate passed';

function fail(message) {
  throw new DeviceTestFailure(message);
}

function step(message) {
  fs.appendFileSync(REPORT, `${new Date().toISOString()} ${message}\n`, { mode: 0o600 });
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function readSecret() {
  let input = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) input += chunk;
  return input.replace(/\r?\n$/, '');
}

async function runProcess(command, args, options = {}) {
  const { input, secret, allowNonzero = false } = options;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: ROOT,
      env: {
        HOME: '/home/w0w',
        USER: 'w0w',
        LANG: 'C',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      },
      stdio: secret === undefined
        ? ['pipe', 'pipe', 'pipe']
        : ['pipe', 'pipe', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', () => reject(new DeviceTestFailure('external process could not start')));
    child.on('close', (code) => {
      const result = {
        code,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
      };
      if (code !== 0 && !allowNonzero) {
        const error = new DeviceTestFailure(`external process failed with exit code ${code}`);
        error.result = result;
        reject(error);
        return;
      }
      resolve(result);
    });
    if (secret !== undefined) child.stdio[3].end(Buffer.from(`${secret}\n`, 'utf8'));
    child.stdin.end(input);
  });
}

async function prepareKnownHosts() {
  const scan = await runProcess('/usr/bin/ssh-keyscan', ['-T', '10', TARGET_IP]);
  if (!scan.stdout.length) fail('ssh-keyscan returned no host key');
  fs.writeFileSync(KNOWN_HOSTS, scan.stdout, { mode: 0o600 });
  const fingerprint = await runProcess('/usr/bin/ssh-keygen', ['-lf', '-'], {
    input: scan.stdout,
  });
  step('ssh_host_keys_begin');
  for (const line of fingerprint.stdout.toString('utf8').trim().split(/\r?\n/)) {
    if (line) step(`ssh_host_key=${line}`);
  }
  step('ssh_host_keys_end');
}

function sshArgs(remoteCommand) {
  return [
    '-d', '3', 'ssh',
    '-o', 'ConnectTimeout=15',
    '-o', 'ConnectionAttempts=1',
    '-o', 'PreferredAuthentications=password,keyboard-interactive',
    '-o', 'PubkeyAuthentication=no',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${KNOWN_HOSTS}`,
    `root@${TARGET_IP}`,
    ...remoteCommand,
  ];
}

async function ssh(password, remoteCommand, options = {}) {
  return runProcess(
    SSHPASS_BIN,
    sshArgs(remoteCommand),
    { ...options, secret: password },
  );
}

async function httpHealthy() {
  try {
    const response = await fetch(`http://${TARGET_IP}/api/health`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    const json = await response.json();
    return response.ok && json?.code === 0 && json?.data?.status === 'ok';
  } catch {
    return false;
  }
}

async function readBootId(password) {
  const result = await ssh(
    password,
    ['cat', '/proc/sys/kernel/random/boot_id'],
  );
  const value = result.stdout.toString('utf8').trim();
  if (!/^[0-9a-f-]{36}$/.test(value)) fail('invalid kernel boot_id');
  return value;
}

async function verifyDevice(password, cycle) {
  const script = fs.readFileSync(DEVICE_SCRIPT);
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (await httpHealthy()) {
      try {
        const result = await ssh(password, ['sh', '-s'], { input: script });
        const output = result.stdout.toString('utf8');
        if (output.includes(EXPECTED_SUCCESS)) {
          fs.writeFileSync(
            path.join(RESULT_DIR, `cycle-${cycle}.txt`),
            output,
            { mode: 0o600 },
          );
          return;
        }
      } catch {}
    }
    await sleep(5000);
  }
  fail(`cycle ${cycle}: device verifier did not become healthy`);
}

async function waitForNewBoot(password, previousBootId, cycle) {
  let offlineObserved = false;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (!await httpHealthy()) {
      offlineObserved = true;
      await sleep(5000);
      continue;
    }
    try {
      const bootId = await readBootId(password);
      if (bootId !== previousBootId) {
        step(`cycle_${cycle}_offline_observed=${offlineObserved ? 'yes' : 'no'}`);
        return bootId;
      }
    } catch {}
    await sleep(5000);
  }
  fail(`cycle ${cycle}: no new boot_id observed`);
}

async function main() {
  if (!TARGET_IP) fail('TARGET_IP is required');
  if (!Number.isInteger(CYCLES) || CYCLES < 1 || CYCLES > 20) {
    fail('REBOOT_CYCLES must be an integer from 1 through 20');
  }
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail('refusing reboot soak without matching --confirm-device');
  }
  if (!fs.existsSync(SSHPASS_BIN)) fail('sshpass executable is missing; configure SSHPASS_BIN');
  if (!fs.existsSync(DEVICE_SCRIPT)) fail('device verifier is missing');
  if (fs.existsSync(RESULT_DIR)) fail('refusing to reuse result directory');

  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  fs.mkdirSync(RESULT_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(REPORT, '', { mode: 0o600 });
  await prepareKnownHosts();

  let bootId = await readBootId(password);
  await verifyDevice(password, 0);
  step(`cycle_0=passed boot_id=${bootId}`);

  for (let cycle = 1; cycle <= CYCLES; cycle += 1) {
    step(`cycle_${cycle}_reboot_requested=yes`);
    await ssh(
      password,
      ['sh', '-c', 'sync; reboot'],
      { allowNonzero: true },
    );
    const nextBootId = await waitForNewBoot(password, bootId, cycle);
    await verifyDevice(password, cycle);
    step(`cycle_${cycle}=passed boot_id=${nextBootId}`);
    bootId = nextBootId;
  }

  step(`SUCCESS: ${CYCLES} Phase 3 reboot cycles passed`);
  process.stdout.write(`SUCCESS: ${REPORT}\n`);
}

main().catch((error) => {
  try {
    fs.mkdirSync(RESULT_DIR, { recursive: true, mode: 0o700 });
    step(`FAILED: ${reportableFailure(error)}`);
  } catch {}
  process.exitCode = 1;
});
