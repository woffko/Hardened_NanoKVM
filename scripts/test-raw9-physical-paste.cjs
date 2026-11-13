#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const CryptoJS = require('../web/node_modules/crypto-js');
const { request } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const BASE_URL = `https://${TARGET_IP}`;
const SAMPLE = 'Paste-RAW9-OK';
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `physical-paste-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');

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

function encryptPassword(password) {
  return encodeURIComponent(CryptoJS.AES.encrypt(password, 'nanokvm-sipeed-2024').toString());
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing physical paste test without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  const context = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, timeout: 30000 });
  try {
    const loginResponse = await context.post('/api/auth/login', {
      data: { username: 'admin', password: encryptPassword(password) },
    });
    const login = await loginResponse.json();
    if (!loginResponse.ok() || login?.code !== 0 || !login?.data?.csrfToken) fail('API login failed');
    const csrfToken = login.data.csrfToken;

    const modeResponse = await context.get('/api/hid/mode');
    const mode = await modeResponse.json();
    if (!modeResponse.ok() || mode?.code !== 0 || mode?.data?.mode !== 'normal') fail('HID mode is not normal');

    const started = Date.now();
    const response = await context.post('/api/hid/paste', {
      headers: { 'x-csrf-token': csrfToken },
      data: { content: SAMPLE, langue: 'en' },
      timeout: 30000,
    });
    const json = await response.json();
    const elapsedMs = Date.now() - started;
    if (!response.ok() || json?.code !== 0) fail(`paste failed: ${json?.msg ?? response.status()}`);

    step(`sample=${SAMPLE}`);
    step(`api_elapsed_ms=${elapsedMs}`);
    step('enter_sent=no');
    step('SUCCESS: paste sample sent through HID paste API; visual confirmation pending');
  } finally {
    await context.dispose();
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
