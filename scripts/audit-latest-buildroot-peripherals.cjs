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
const EXPECTED_ED25519 = 'SHA256:IZackVzmTMVDUGZJ8YsaqK7eUe1nGy+aVRKlVMxnqs4';
const SSHPASS = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `peripheral-audit-${TARGET_IP}-${runId}`);
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
      } else {
        resolve(Buffer.concat(stdout));
      }
    });
    if (secret !== undefined) child.stdio[3].end(secret);
    if (input !== undefined && child.stdin) child.stdin.end(input);
    else if (child.stdin) child.stdin.end();
  });
}

async function prepareKnownHosts() {
  const keys = await run('/usr/bin/ssh-keyscan', ['-T', '5', TARGET_IP]);
  const fingerprints = await run('/usr/bin/ssh-keygen', ['-lf', '-'], keys);
  if (!fingerprints.toString('utf8').includes(`${EXPECTED_ED25519} ${TARGET_IP} (ED25519)`)) {
    fail('unexpected SSH fingerprint');
  }
  fs.writeFileSync(knownHostsPath, keys, { mode: 0o600 });
}

async function ssh(password, command) {
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
  return output.toString('utf8');
}

function encryptPassword(password) {
  return encodeURIComponent(CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString());
}

async function login(context, password) {
  const response = await context.post('/api/auth/login', {
    data: { username: 'admin', password: encryptPassword(password) },
    timeout: 30000,
  });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0 || !json?.data?.csrfToken) {
    fail(`login failed: ${json?.msg ?? response.status()}`);
  }
}

async function get(context, pathname) {
  const response = await context.get(pathname, { timeout: 60000 });
  const json = await response.json();
  if (!response.ok() || json?.code !== 0) fail(`${pathname} failed: ${json?.msg ?? response.status()}`);
  return json.data;
}

function parseFields(text) {
  const fields = new Map();
  for (const line of text.split(/\r?\n/)) {
    const separator = line.indexOf('=');
    if (separator > 0) fields.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return fields;
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing peripheral audit without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  await prepareKnownHosts();

  const context = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 60000 });
  try {
    await login(context, password);
    const [hardware, gpio, oled, virtualDevice, hdmi, mouseJiggler, hidMode, usbWakeup, wifi] = await Promise.all([
      get(context, '/api/vm/hardware'),
      get(context, '/api/vm/gpio'),
      get(context, '/api/vm/oled'),
      get(context, '/api/vm/device/virtual'),
      get(context, '/api/vm/hdmi'),
      get(context, '/api/vm/mouse-jiggler'),
      get(context, '/api/hid/mode'),
      get(context, '/api/hid/usb-wakeup'),
      get(context, '/api/network/wifi'),
    ]);
    const apiSummary = {
      hardwareVersion: hardware?.version || '',
      gpio: { pwr: gpio?.pwr, hdd: gpio?.hdd },
      oled: { exist: oled?.exist, sleep: oled?.sleep },
      virtualDevice,
      hdmiEnabled: hdmi?.enabled,
      mouseJiggler,
      hidMode: hidMode?.mode || '',
      usbWakeupEnabled: usbWakeup?.enabled,
      wifi: {
        supported: wifi?.supported,
        apMode: wifi?.apMode,
        connected: wifi?.connected,
        ssidPresent: Boolean(wifi?.ssid),
      },
    };
    fs.writeFileSync(path.join(resultDir, 'api-summary.json'), `${JSON.stringify(apiSummary, null, 2)}\n`, { mode: 0o600 });
    if (!apiSummary.hardwareVersion) fail('hardware version is empty');
    if (typeof apiSummary.gpio.pwr !== 'boolean' || typeof apiSummary.gpio.hdd !== 'boolean') fail('GPIO LED state is invalid');
    if (apiSummary.oled.exist !== true) fail('OLED is not detected');
    if (apiSummary.hdmiEnabled !== true) fail('HDMI is not enabled');
    if (apiSummary.hidMode !== 'normal') fail(`unexpected HID mode: ${apiSummary.hidMode}`);
    step(`hardware_version=${apiSummary.hardwareVersion}`);
    step(`gpio_power_led=${apiSummary.gpio.pwr}`);
    step(`gpio_hdd_led=${apiSummary.gpio.hdd}`);
    step(`oled_exist=${apiSummary.oled.exist}`);
    step(`oled_sleep=${apiSummary.oled.sleep}`);
    step(`virtual_network=${String(apiSummary.virtualDevice?.network)}`);
    step(`virtual_disk=${String(apiSummary.virtualDevice?.disk)}`);
    step(`wifi_supported=${String(apiSummary.wifi.supported)}`);
    step(`wifi_connected=${String(apiSummary.wifi.connected)}`);
  } finally {
    await context.dispose();
  }

  const sshText = await ssh(password, String.raw`set -eu
alive_pid() {
  FILE="$1"
  PID="$(cat "$FILE" 2>/dev/null || true)"
  [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null && printf '%s' "$PID"
}
HWMON_PID="$(alive_pid /tmp/nanokvm-hwmon.pid || true)"
WATCHDOG_PID="$(/usr/libexec/nanokvm-native-ctl --watchdog status runtime || true)"
KVM_PID=''
for PROC in /proc/[0-9]*; do
  CMD="$(tr '\0' ' ' < "$PROC/cmdline" 2>/dev/null || true)"
  case "$CMD" in
    /lib/ld-musl-riscv64v0p7_xthead.so.1*'/tmp/kvm_system/kvm_system'*) KVM_PID="$(basename "$PROC")"; break ;;
  esac
done
NOW="$(date +%s)"
SNAPSHOT_MS="$(sed -n 's/.*"generated_at_unix_ms":[[:space:]]*\([0-9][0-9]*\).*/\1/p' /run/nanokvm-hwmon-state.json 2>/dev/null | head -n 1)"
[ -n "$SNAPSHOT_MS" ] || SNAPSHOT_MS=0
printf 'HWMON_PID=%s\n' "$HWMON_PID"
printf 'WATCHDOG_PID=%s\n' "$WATCHDOG_PID"
printf 'KVM_SYSTEM_PID=%s\n' "$KVM_PID"
printf 'HWMON_SNAPSHOT=%s\n' "$([ -s /run/nanokvm-hwmon-state.json ] && echo present || echo missing)"
printf 'HWMON_AGE_SECONDS=%s\n' "$((NOW - SNAPSHOT_MS / 1000))"
printf 'HWMON_SCHEMA=%s\n' "$(grep -q 'nanokvm-hwmon/v1' /run/nanokvm-hwmon-state.json 2>/dev/null && echo ok || echo missing)"
printf 'HWMON_USB_CONFIGURED=%s\n' "$(grep -q '"udc_state": "configured"' /run/nanokvm-hwmon-state.json 2>/dev/null && echo yes || echo no)"
printf 'HWMON_HDMI_ACTIVE=%s\n' "$(grep -q '"active": true' /run/nanokvm-hwmon-state.json 2>/dev/null && echo yes || echo no)"
printf 'RUST_HWMON_FLAG=%s\n' "$([ -f /etc/kvm/rust_hwmon_enabled ] && echo present || echo missing)"
printf 'OLED_EXIST_FLAG=%s\n' "$([ -f /etc/kvm/oled_exist ] && echo present || echo missing)"
printf 'OLED_LOG_ACTIVE=%s\n' "$(grep -q 'Rust hwmon passive state active' /tmp/kvm_system.log 2>/dev/null && echo yes || echo no)"
printf 'I2C4=%s\n' "$([ -c /dev/i2c-4 ] && echo char || echo missing)"
printf 'LT6911_SENSOR_LIB=%s\n' "$([ -s /mnt/system/usr/lib/libsns_lt6911.so ] && echo present || echo missing)"
printf 'SENSOR_CONFIG=%s\n' "$([ -s /mnt/data/sensor_cfg.ini ] && echo present || echo missing)"
printf 'INPUT_EVENT_COUNT=%s\n' "$(find /dev/input -maxdepth 1 -name 'event*' 2>/dev/null | wc -l)"
printf 'LED_CLASS_COUNT=%s\n' "$(find /sys/class/leds -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
printf 'WATCHDOG_CHAR=%s\n' "$([ -c /dev/watchdog ] && echo present || echo missing)"
printf 'WLAN0=%s\n' "$([ -d /sys/class/net/wlan0 ] && echo present || echo missing)"
printf 'WIFI_EXIST_FLAG=%s\n' "$([ -f /etc/kvm/wifi_exist ] && echo present || echo missing)"
printf 'USB0=%s\n' "$([ -d /sys/class/net/usb0 ] && echo present || echo missing)"
printf 'CRITICAL_MODULES=%s\n' "$(grep -q '^soph_sys ' /proc/modules && grep -q '^soph_vcodec ' /proc/modules && grep -q '^soph_vi ' /proc/modules && echo ok || echo missing)"
printf 'SYSTEM_UPDATE_WATCHDOG=%s\n' "$(/usr/libexec/nanokvm-native-ctl --watchdog status update >/dev/null 2>&1 && echo present || echo absent)"
printf 'DMESG_ALERTS=%s\n' "$(dmesg 2>/dev/null | grep -Eic 'oops|panic|segfault|BUG:' || true)"
printf 'PERIPHERAL_LOG_ALERTS_BEGIN\n'
{ tail -n 160 /tmp/kvm_system.log 2>/dev/null; tail -n 160 /tmp/nanokvm-hwmon.log 2>/dev/null; } | grep -Ei 'segfault|panic|fatal|unsupported relocation|Error loading shared library' || true
printf 'PERIPHERAL_LOG_ALERTS_END\n'
`);
  fs.writeFileSync(path.join(resultDir, 'ssh-summary.txt'), sshText, { mode: 0o600 });
  const fields = parseFields(sshText);
  for (const expected of [
    ['HWMON_PID', true], ['WATCHDOG_PID', true], ['KVM_SYSTEM_PID', true],
    ['HWMON_SNAPSHOT', 'present'], ['HWMON_SCHEMA', 'ok'],
    ['HWMON_USB_CONFIGURED', 'yes'], ['HWMON_HDMI_ACTIVE', 'yes'],
    ['RUST_HWMON_FLAG', 'present'], ['OLED_EXIST_FLAG', 'present'], ['OLED_LOG_ACTIVE', 'yes'],
    ['I2C4', 'char'], ['LT6911_SENSOR_LIB', 'present'], ['SENSOR_CONFIG', 'present'],
    ['CRITICAL_MODULES', 'ok'], ['SYSTEM_UPDATE_WATCHDOG', 'absent'], ['DMESG_ALERTS', '0'],
  ]) {
    const value = fields.get(expected[0]) || '';
    if (expected[1] === true ? !/^[0-9]+$/.test(value) : value !== expected[1]) {
      fail(`peripheral SSH check failed: ${expected[0]}=${value}`);
    }
  }
  const snapshotAge = Number(fields.get('HWMON_AGE_SECONDS') || '9999');
  if (snapshotAge < 0 || snapshotAge > 10) fail(`hwmon snapshot age is ${snapshotAge}s`);
  if (!sshText.includes('PERIPHERAL_LOG_ALERTS_BEGIN\nPERIPHERAL_LOG_ALERTS_END')) {
    fail('peripheral logs contain fatal loader/runtime alerts');
  }
  for (const name of ['HWMON_PID', 'WATCHDOG_PID', 'KVM_SYSTEM_PID', 'HWMON_AGE_SECONDS', 'INPUT_EVENT_COUNT', 'LED_CLASS_COUNT', 'WATCHDOG_CHAR', 'WLAN0', 'WIFI_EXIST_FLAG', 'USB0']) {
    step(`${name.toLowerCase()}=${fields.get(name) || ''}`);
  }
  step('SUCCESS: read-only peripheral, hwmon, watchdog, OLED, sensor, GPIO, and Wi-Fi inventory passed');
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
