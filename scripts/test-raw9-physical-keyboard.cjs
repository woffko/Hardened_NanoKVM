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
const SAMPLE = 'NanoKVM-RAW9-HID-OK-3';
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `physical-keyboard-${TARGET_IP}-${runId}`);
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

async function typeHumanSequence(page, text) {
  for (const character of text) {
    const isUpper = character >= 'A' && character <= 'Z';
    const key = isUpper ? character.toLowerCase() : character;
    if (isUpper) {
      await page.keyboard.down('Shift');
      await page.waitForTimeout(60);
    }
    await page.keyboard.down(key);
    await page.waitForTimeout(70);
    await page.keyboard.up(key);
    if (isUpper) {
      await page.waitForTimeout(50);
      await page.keyboard.up('Shift');
    }
    await page.waitForTimeout(100);
  }
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing physical keyboard test without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  const browser = await chromium.launch({ headless: true, executablePath: CHROMIUM });
  const context = await browser.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const pageErrors = [];
  const consoleErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });

  try {
    const loginResponse = await context.request.post('/api/auth/login', {
      data: { username: 'admin', password: encryptPassword(password) },
    });
    const login = await loginResponse.json();
    if (!loginResponse.ok() || login?.code !== 0 || !login?.data?.csrfToken) fail('API login failed');

    const modeResponse = await context.request.get('/api/hid/mode');
    const mode = await modeResponse.json();
    if (!modeResponse.ok() || mode?.code !== 0 || mode?.data?.mode !== 'normal') {
      fail(`HID mode is not normal: ${mode?.data?.mode ?? 'unknown'}`);
    }

    const wsReady = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('HID websocket did not become ready')), 15000);
      page.on('websocket', (socket) => {
        if (!socket.url().endsWith('/api/ws')) return;
        const ready = () => {
          clearTimeout(timer);
          resolve();
        };
        socket.on('framereceived', ready);
        socket.on('framesent', ready);
      });
    });
    await page.goto('/#/', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.locator('#kvm-pointer-surface').waitFor({ state: 'visible', timeout: 45000 });
    await wsReady;
    step('hid_websocket=ready');
    await typeHumanSequence(page, SAMPLE);
    await page.keyboard.down('Enter');
    await page.waitForTimeout(70);
    await page.keyboard.up('Enter');
    await page.waitForTimeout(1000);

    step(`sample=${SAMPLE}`);
    step('enter=sent');
    step(`page_errors=${pageErrors.length}`);
    step(`console_errors=${consoleErrors.length}`);
    if (pageErrors.length || consoleErrors.length) fail('browser errors occurred during physical keyboard test');
    step('SUCCESS: keyboard sample sent through live NanoKVM UI HID path; visual confirmation pending');
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
