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
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `network-audit-${TARGET_IP}-${runId}`);
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

function parseFields(text) {
  const fields = new Map();
  for (const line of text.split(/\r?\n/)) {
    const index = line.indexOf('=');
    if (index > 0) fields.set(line.slice(0, index), line.slice(index + 1));
  }
  return fields;
}

function csv(values) {
  return values.join(',');
}

function encryptPassword(password) {
  return encodeURIComponent(CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString());
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing network audit without --confirm-device ${TARGET_IP}`);
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

    const [dnsResponse, ipv6Response] = await Promise.all([
      context.get('/api/network/dns'),
      context.get('/api/network/ipv6'),
    ]);
    const dns = await dnsResponse.json();
    const ipv6 = await ipv6Response.json();
    if (!dnsResponse.ok() || dns?.code !== 0 || !dns?.data) fail('DNS API failed');
    if (!ipv6Response.ok() || ipv6?.code !== 0 || !ipv6?.data) fail('IPv6 API failed');

    const state = (await run(
      SSHPASS,
      [
        '-d', '3', 'ssh', '-o', 'ConnectTimeout=10', '-o', 'PreferredAuthentications=password,keyboard-interactive',
        '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHostsPath}`,
        `root@${TARGET_IP}`,
        `set -eu
dns_csv() { awk '$1 == "nameserver" { if (seen++) printf ","; printf "%s", $2 } END { print "" }' "$1" 2>/dev/null || true; }
plain_csv() { awk 'NF && $1 !~ /^#/ { if (seen++) printf ","; printf "%s", $1 } END { print "" }' "$1" 2>/dev/null || true; }
printf 'ETH_NODHCP=%s\\n' "$(tr '\\n' ' ' < /boot/eth.nodhcp | sed 's/[[:space:]]*$//')"
printf 'DNS_MODE=%s\\n' "$(cat /etc/kvm/network/dns.mode 2>/dev/null || true)"
printf 'DNS_SERVERS=%s\\n' "$(plain_csv /etc/kvm/network/dns.servers)"
printf 'BOOT_DNS=%s\\n' "$(dns_csv /boot/resolv.conf)"
printf 'EFFECTIVE_DNS=%s\\n' "$(dns_csv /etc/resolv.conf)"
printf 'DNS_TOTAL=%s\\n' "$(awk '$1 == "nameserver" { count++ } END { print count + 0 }' /etc/resolv.conf)"
printf 'DNS_UNIQUE=%s\\n' "$(awk '$1 == "nameserver" { seen[$2]=1 } END { for (item in seen) count++; print count + 0 }' /etc/resolv.conf)"
printf 'DEFAULT_ROUTE=%s\\n' "$(ip route show default | head -n 1)"
printf 'ETH_ADDRESS=%s\\n' "$(ip -4 -o addr show dev eth0 | awk '{print $4}' | head -n 1)"
printf 'IPV6_MODE=%s\\n' "$(cat /boot/eth.ipv6.mode 2>/dev/null || true)"
`,
      ],
      undefined,
      Buffer.from(`${password}\n`, 'utf8'),
    )).toString('utf8');
    fs.writeFileSync(path.join(resultDir, 'ssh-state.txt'), state, { mode: 0o600 });
    fs.writeFileSync(path.join(resultDir, 'api-state.json'), `${JSON.stringify({ dns: dns.data, ipv6: ipv6.data }, null, 2)}\n`, { mode: 0o600 });
    const fields = parseFields(state);

    const servers = dns.data.servers || [];
    const effective = dns.data.effective || [];
    if (dns.data.mode !== 'manual') fail(`DNS mode=${dns.data.mode}`);
    if (!dns.data.config || dns.data.config.address !== TARGET_IP || dns.data.config.gateway !== '10.0.87.5') {
      fail('static network API configuration mismatch');
    }
    if (dns.data.info?.address?.split('/')[0] !== TARGET_IP || dns.data.info?.gateway !== '10.0.87.5') {
      fail('effective network API information mismatch');
    }
    if (!servers.length || csv(servers) !== csv(effective)) fail('manual and effective DNS differ');
    if (new Set(servers).size !== servers.length) fail('DNS API contains duplicate servers');
    for (const field of ['BOOT_DNS', 'EFFECTIVE_DNS']) {
      if (fields.get(field) !== csv(servers)) fail(`${field} differs from DNS API`);
    }
    const storedMode = fields.get('DNS_MODE') || '';
    const storedServers = fields.get('DNS_SERVERS') || '';
    if (storedMode && storedMode !== 'manual') fail(`persisted DNS mode=${storedMode}`);
    if (storedServers && storedServers !== csv(servers)) fail('persisted DNS servers differ from DNS API');
    if (!storedMode && !fields.get('BOOT_DNS')) fail('legacy manual DNS source is missing');
    if (fields.get('DNS_TOTAL') !== fields.get('DNS_UNIQUE')) fail('effective resolver contains duplicates');
    if (fields.get('ETH_NODHCP') !== '10.0.87.133/24 10.0.87.5') fail('static IPv4 file mismatch');
    if (fields.get('ETH_ADDRESS') !== '10.0.87.133/24') fail('effective IPv4 address mismatch');
    if (!fields.get('DEFAULT_ROUTE')?.includes('via 10.0.87.5 dev eth0')) fail('default route mismatch');

    step('mode=manual');
    step(`servers=${csv(servers)}`);
    step(`effective=${csv(effective)}`);
    step(`persistence_source=${storedMode ? 'network-config' : 'legacy-boot-resolv'}`);
    step(`static_address=${dns.data.config.address}`);
    step(`gateway=${dns.data.config.gateway}`);
    step(`ipv6_mode=${ipv6.data.mode}`);
    step('SUCCESS: DNS API, persisted files, effective resolver, address, and route are consistent');
  } finally {
    await context.dispose();
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
