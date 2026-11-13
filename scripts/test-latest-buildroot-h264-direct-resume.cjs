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
const resultDir = path.join(ROOT, 'build/latestbuildroot/device-tests', `h264-direct-resume-${TARGET_IP}-${runId}`);
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
    fail(`refusing H264 resume test without --confirm-device ${TARGET_IP}`);
  }
  fs.mkdirSync(resultDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(reportPath, '', { mode: 0o600 });
  const password = await readSecret();
  if (!password) fail('secret stdin was empty');

  const browser = await chromium.launch({ headless: true, executablePath: CHROMIUM });
  const context = await browser.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  try {
    const loginResponse = await context.request.post('/api/auth/login', {
      data: { username: 'admin', password: encryptPassword(password) },
    });
    const login = await loginResponse.json();
    if (!loginResponse.ok() || login?.code !== 0 || !login?.data?.csrfToken) fail('API login failed');
    const csrfToken = login.data.csrfToken;

    const [systemResponse, appResponse] = await Promise.all([
      context.request.get('/api/system-update/version'),
      context.request.get('/api/application/version'),
    ]);
    const system = await systemResponse.json();
    const app = await appResponse.json();
    if (system?.data?.current?.version !== EXPECTED_SYSTEM || app?.data?.current !== EXPECTED_APP) {
      fail(`unexpected device state ${system?.data?.current?.version}/${app?.data?.current}`);
    }

    await page.goto('/api/health', { waitUntil: 'domcontentloaded', timeout: 30000 });
    const result = await page.evaluate(async ({ token }) => {
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const setMode = async (value) => {
        const response = await fetch('/api/vm/screen', {
          method: 'POST',
          credentials: 'include',
          headers: { 'content-type': 'application/json', 'x-csrf-token': token },
          body: JSON.stringify({ type: 'type', value }),
        });
        const json = await response.json();
        if (!response.ok || json?.code !== 0) throw new Error(`set mode ${value} failed`);
      };

      let socket;
      let openCount = 0;
      let packets = 0;
      let bytes = 0;
      let unexpectedClose = false;
      try {
        await setMode(1);
        socket = new WebSocket(`wss://${location.host}/api/stream/h264/direct`);
        socket.binaryType = 'arraybuffer';
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('initial H264 websocket timeout')), 10000);
          socket.onopen = () => {
            openCount += 1;
            clearTimeout(timer);
            resolve();
          };
          socket.onerror = () => {
            clearTimeout(timer);
            reject(new Error('initial H264 websocket error'));
          };
        });
        socket.onmessage = (event) => {
          if (event.data instanceof ArrayBuffer) {
            packets += 1;
            bytes += event.data.byteLength;
          }
        };
        socket.onclose = () => {
          unexpectedClose = true;
        };

        await sleep(5000);
        const initialPackets = packets;
        const initialBytes = bytes;
        await setMode(0);
        await sleep(3000);
        const packetsAfterMjpeg = packets;
        await setMode(1);
        await sleep(6000);
        const resumedPackets = packets - packetsAfterMjpeg;
        const resumedBytes = bytes - initialBytes;

        return {
          openCount,
          initialPackets,
          initialBytes,
          packetsDuringMjpeg: packetsAfterMjpeg - initialPackets,
          resumedPackets,
          resumedBytes,
          unexpectedClose,
        };
      } finally {
        if (socket && socket.readyState === WebSocket.OPEN) socket.close();
        await setMode(0).catch(() => {});
      }
    }, { token: csrfToken });

    step(`websocket_open_count=${result.openCount}`);
    step(`initial=${result.initialPackets}/${result.initialBytes}`);
    step(`packets_during_mjpeg=${result.packetsDuringMjpeg}`);
    step(`resumed=${result.resumedPackets}/${result.resumedBytes}`);
    step(`unexpected_close=${result.unexpectedClose}`);
    if (result.openCount !== 1 || result.unexpectedClose) fail('H264 Direct websocket reconnected or closed');
    if (result.initialPackets < 5 || result.initialBytes < 10000) fail('initial H264 Direct phase produced insufficient data');
    if (result.resumedPackets < 5 || result.resumedBytes < 10000) fail('same H264 Direct websocket did not resume');
    step('SUCCESS: same H264 Direct websocket resumed after global MJPEG mode and required no WebRTC workaround');
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  try { step(`FAILED: ${error.message}`); } catch {}
  process.exitCode = 1;
});
