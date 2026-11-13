#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const CryptoJS = require('../web/node_modules/crypto-js');
const { chromium } = require('/home/w0w/.local/share/playwright/node_modules/playwright');

const ROOT = path.resolve(__dirname, '..');
const TARGET_IP = '10.0.87.133';
const BASE_URL = `https://${TARGET_IP}`;
const EXPECTED_SYSTEM = process.env.EXPECTED_SYSTEM_VERSION || '0.3.0-raw.10';
const EXPECTED_APP = process.env.EXPECTED_APP_VERSION || '2.0.40';
const CHROMIUM = '/home/w0w/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome';
const runId = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z');
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `browser-smoke-${TARGET_IP}-${runId}`);
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

async function waitForHash(page, expected) {
  await page.waitForFunction((hash) => window.location.hash === hash, expected, { timeout: 30000 });
}

async function main() {
  if (process.argv[2] !== '--confirm-device' || process.argv[3] !== TARGET_IP) {
    fail(`refusing browser smoke without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');
  if (!fs.existsSync(CHROMIUM)) fail('local Playwright Chromium is missing');

  const browser = await chromium.launch({ headless: true, executablePath: CHROMIUM });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: BASE_URL });
  const page = await context.newPage();
  const pageErrors = [];
  const consoleErrors = [];
  const failedRequests = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('requestfailed', (request) => {
    const url = new URL(request.url());
    const errorText = request.failure()?.errorText || 'failed';
    if (errorText.includes('ERR_ABORTED')) return;
    if (url.hostname === TARGET_IP) failedRequests.push(`${url.pathname}:${errorText}`);
  });

  try {
    await page.goto('/#/auth/login', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.locator('form input').first().fill('admin');
    await page.locator('form input[type="password"]').first().fill(password);
    await page.locator('form button[type="submit"]').click();
    await page.locator('#kvm-pointer-surface').waitFor({ state: 'visible', timeout: 45000 });
    await waitForHash(page, '#/');
    step('ui_login=ok');

    const versions = await page.evaluate(async () => {
      const [appResponse, systemResponse] = await Promise.all([
        fetch('/api/application/version', { credentials: 'include' }),
        fetch('/api/system-update/version', { credentials: 'include' }),
      ]);
      return {
        app: await appResponse.json(),
        system: await systemResponse.json(),
      };
    });
    if (versions.app?.code !== 0 || versions.app?.data?.current !== EXPECTED_APP) {
      fail(`browser app version mismatch: ${versions.app?.data?.current}`);
    }
    if (versions.system?.code !== 0 || versions.system?.data?.current?.version !== EXPECTED_SYSTEM) {
      fail(`browser system version mismatch: ${versions.system?.data?.current?.version}`);
    }
    step(`app_version=${versions.app.data.current}`);
    step(`system_version=${versions.system.data.current.version}`);

    const screen = page.locator('#screen');
    await screen.waitFor({ state: 'visible', timeout: 30000 });
    await page.waitForFunction(() => {
      const element = document.getElementById('screen');
      if (element instanceof HTMLImageElement) return element.naturalWidth > 0 && element.naturalHeight > 0;
      if (element instanceof HTMLCanvasElement) return element.width > 0 && element.height > 0;
      if (element instanceof HTMLVideoElement) return element.videoWidth > 0 && element.videoHeight > 0;
      return false;
    }, undefined, { timeout: 30000 });
    const screenState = await screen.evaluate((element) => ({
      tag: element.tagName,
      width: element instanceof HTMLImageElement ? element.naturalWidth : element.clientWidth,
      height: element instanceof HTMLImageElement ? element.naturalHeight : element.clientHeight,
    }));
    if (screenState.width <= 0 || screenState.height <= 0) fail('browser video surface has no rendered dimensions');
    step(`video_surface=${screenState.tag}:${screenState.width}x${screenState.height}`);

    await page.goto('/#/terminal', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await waitForHash(page, '#/terminal');
    await page.locator('form input[type="password"]').waitFor({ state: 'visible', timeout: 30000 });
    if (await page.locator('form input').count() < 2) fail('terminal unlock form is incomplete');
    step('route_terminal=ok');

    await page.goto('/#/auth/password', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await waitForHash(page, '#/auth/password');
    await page.waitForFunction(
      () => document.querySelectorAll('form input[type="password"]').length >= 2,
      undefined,
      { timeout: 30000 },
    );
    const passwordFormInputs = await page.locator('form input').count();
    const passwordFields = await page.locator('form input[type="password"]').count();
    step(`password_route_inputs=${passwordFormInputs}`);
    step(`password_route_password_fields=${passwordFields}`);
    if (passwordFormInputs < 3 || passwordFields < 2) fail('password route form is incomplete');
    step('route_password=ok');

    await page.goBack({ waitUntil: 'domcontentloaded' });
    await waitForHash(page, '#/terminal');
    await page.goForward({ waitUntil: 'domcontentloaded' });
    await waitForHash(page, '#/auth/password');
    step('router_back_forward=ok');

    await page.goto('/#/', { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.locator('#kvm-pointer-surface').waitFor({ state: 'visible', timeout: 30000 });
    step('protected_root_reload=ok');
    await page.waitForTimeout(2000);

    const ignoredConsoleErrors = consoleErrors.filter((message) =>
      !message.includes('ResizeObserver loop') && !message.includes('favicon.ico')
      && !message.includes('ERR_ABORTED')
    );
    if (pageErrors.length) fail(`browser page errors: ${pageErrors.join(' | ')}`);
    if (ignoredConsoleErrors.length) fail(`browser console errors: ${ignoredConsoleErrors.join(' | ')}`);
    if (failedRequests.length) fail(`browser same-origin request failures: ${failedRequests.join(' | ')}`);
    step('browser_errors=0');
    step('SUCCESS: React Router login, protected routes, navigation, API, and live video smoke passed');
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
