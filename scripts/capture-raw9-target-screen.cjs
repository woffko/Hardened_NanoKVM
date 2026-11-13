#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const CryptoJS = require('../web/node_modules/crypto-js');
const { chromium } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const BASE_URL = `https://${TARGET_IP}`;
const CHROMIUM = '/home/w0w/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome';
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `physical-host-screen-${TARGET_IP}-${runId}`);
const reportPath = path.join(resultDir, 'report.txt');
const screenshotPath = path.join(resultDir, 'target-screen.png');

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
    fail(`refusing screen capture without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  const browser = await chromium.launch({ headless: true, executablePath: CHROMIUM });
  const context = await browser.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 } });
  const page = await context.newPage();
  try {
    const loginResponse = await context.request.post('/api/auth/login', {
      data: { username: 'admin', password: encryptPassword(password) },
    });
    const login = await loginResponse.json();
    if (!loginResponse.ok() || login?.code !== 0 || !login?.data?.csrfToken) fail('API login failed');

    await page.goto('/#/', { waitUntil: 'domcontentloaded', timeout: 30000 });
    const surface = page.locator('#kvm-pointer-surface');
    await surface.waitFor({ state: 'visible', timeout: 45000 });
    await page.waitForFunction(() => {
      const image = document.querySelector('#kvm-pointer-surface img');
      return image instanceof HTMLImageElement && image.naturalWidth > 0 && image.naturalHeight > 0;
    }, undefined, { timeout: 45000 });
    await page.waitForTimeout(2000);
    await surface.screenshot({ path: screenshotPath });
    const dimensions = await surface.locator('img').first().evaluate((image) => ({
      width: image.naturalWidth,
      height: image.naturalHeight,
    }));
    step(`video=${dimensions.width}x${dimensions.height}`);
    step(`screenshot=${path.relative(ROOT, screenshotPath)}`);
    step('SUCCESS: target video screenshot captured without HID input');
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
