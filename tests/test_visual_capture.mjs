import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { createServer } from 'node:http';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtureRoot = path.join(root, 'tests', 'fixtures', 'visual-evidence');
const captureScript = path.join(root, 'scripts', 'pipeline_visual_capture.mjs');
let artifactRoot;
let server;
let rejectedServer;
let baseUrl;
let rejectedBaseUrl;
let rejectedConnectionCount = 0;
let rejectedRequestCount = 0;
let sameSurfaceAssetRequestCount = 0;
let sameSurfaceSocketCount = 0;
let rejectedDatagramCount = 0;
let rejectedDatagramServer;
let rejectedWebTransportUrl;
let rejectedWebRtcUrl;
const sameSurfaceSockets = new Set();

before(async () => {
  artifactRoot = await mkdtemp(path.join(os.tmpdir(), 'visual-capture-test-'));
  rejectedDatagramServer = createSocket('udp4');
  rejectedDatagramServer.on('message', () => {
    rejectedDatagramCount += 1;
  });
  await new Promise((resolve) => rejectedDatagramServer.bind(0, '127.0.0.1', resolve));
  rejectedWebTransportUrl = `https://127.0.0.1:${rejectedDatagramServer.address().port}/webtransport-received`;
  rejectedWebRtcUrl = `stun:127.0.0.1:${rejectedDatagramServer.address().port}`;
  rejectedServer = createServer((_request, response) => {
    rejectedRequestCount += 1;
    response.writeHead(204).end();
  });
  rejectedServer.on('upgrade', (_request, socket) => {
    rejectedRequestCount += 1;
    socket.destroy();
  });
  rejectedServer.on('connection', () => {
    rejectedConnectionCount += 1;
  });
  await new Promise((resolve) => rejectedServer.listen(0, '127.0.0.1', resolve));
  rejectedBaseUrl = `http://127.0.0.1:${rejectedServer.address().port}`;

  server = createServer(async (request, response) => {
    try {
      const requestedUrl = new URL(request.url, 'http://localhost');
      const pathname = requestedUrl.pathname;
      if (pathname === '/initial-redirect') {
        response.writeHead(302, { location: `${rejectedBaseUrl}/redirect-received` }).end();
        return;
      }
      if (pathname === '/target-redirect') {
        response.writeHead(302, { location: requestedUrl.searchParams.get('target') }).end();
        return;
      }
      if (pathname === '/meta-navigation.html') {
        const target = requestedUrl.searchParams.get('target');
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(
          `<!doctype html><html><head><meta http-equiv="refresh" content="0;url=${target}"><title>Meta navigation</title></head><body>Meta navigation fixture</body></html>`,
        );
        return;
      }
      if (pathname === '/shared-worker-webtransport.js') {
        const target = requestedUrl.searchParams.get('target');
        response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' }).end(
          `try { new WebTransport(${JSON.stringify(target)}); } catch {}`,
        );
        return;
      }
      if (pathname === '/shared-worker-webtransport-relay-replacement.js') {
        const target = requestedUrl.searchParams.get('target');
        response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' }).end(`
          MessagePort.prototype.postMessage = () => {};
          try { new WebTransport(${JSON.stringify(target)}); } catch {}
        `);
        return;
      }
      if (pathname === '/shared-worker-message.js') {
        response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' }).end(
          "addEventListener('connect', (event) => event.ports[0].postMessage('Allowed same-surface worker'));",
        );
        return;
      }
      if (pathname === '/same-surface-asset.svg') {
        sameSurfaceAssetRequestCount += 1;
        response.writeHead(200, { 'content-type': 'image/svg+xml' }).end(
          '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><rect width="20" height="20" fill="#7746ec"/></svg>',
        );
        return;
      }
      const requestedFile = pathname === '/' ? 'occlusion.html' : pathname.slice(1);
      const resolved = path.resolve(fixtureRoot, requestedFile);
      if (!resolved.startsWith(`${fixtureRoot}${path.sep}`)) {
        response.writeHead(403).end('Forbidden');
        return;
      }
      const body = await readFile(resolved);
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(body);
    } catch {
      response.writeHead(404).end('Not found');
    }
  });
  server.on('upgrade', (request, socket) => {
    if (new URL(request.url, 'http://localhost').pathname !== '/same-surface-socket') {
      socket.destroy();
      return;
    }
    sameSurfaceSocketCount += 1;
    sameSurfaceSockets.add(socket);
    socket.on('close', () => sameSurfaceSockets.delete(socket));
    const accept = createHash('sha1')
      .update(`${request.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');
    socket.end(
      'HTTP/1.1 101 Switching Protocols\r\n'
      + 'Upgrade: websocket\r\n'
      + 'Connection: Upgrade\r\n'
      + `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
      + '\u0088\u0000',
      'latin1',
    );
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  for (const socket of sameSurfaceSockets) socket.destroy();
  rejectedDatagramServer.close();
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  await new Promise((resolve, reject) => rejectedServer.close((error) => (error ? reject(error) : resolve())));
  await rm(artifactRoot, { recursive: true, force: true });
});

function sanitizedStderr(stderr) {
  return String(stderr || '')
    .replace(/\u001b\[[0-9;]*m/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .trim()
    .slice(0, 2_000);
}

async function capture(
  scenario,
  {
    click = [], env = {}, height = 600, page = 'occlusion.html', query = {}, width = 800,
  } = {},
) {
  const directory = path.join(artifactRoot, scenario);
  const reportPath = path.join(directory, 'report.json');
  const captureUrl = new URL(`/${page}`, baseUrl);
  captureUrl.searchParams.set('case', scenario);
  for (const [key, value] of Object.entries(query)) captureUrl.searchParams.set(key, value);
  const args = [
    captureScript,
    '--url', captureUrl.href,
    '--surface', 'fixture',
    '--state', scenario,
    '--width', String(width),
    '--height', String(height),
    '--screenshot', path.join(directory, 'capture.png'),
    '--report', reportPath,
    '--manifest', path.join(directory, 'manifest.json'),
    '--timeout-ms', '10000',
  ];
  for (const selector of click) args.push('--click', selector);
  let status = 0;
  let stderr = '';
  try {
    await execFileAsync(process.execPath, args, {
      env: { ...process.env, ...env },
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (error) {
    status = error.code;
    stderr = error.stderr;
  }
  let report;
  try {
    report = JSON.parse(await readFile(reportPath, 'utf8'));
  } catch (error) {
    const captureError = sanitizedStderr(stderr);
    throw new Error(
      `visual capture exited before writing its report${captureError ? `: ${captureError}` : ''}`,
      { cause: error },
    );
  }
  return { status, stderr, report };
}

async function boundaryRejectedCapture(
  scenario,
  { click = [], page, query = {} },
) {
  const directory = path.join(artifactRoot, scenario);
  const screenshotPath = path.join(directory, 'capture.png');
  const reportPath = path.join(directory, 'report.json');
  const manifestPath = path.join(directory, 'manifest.json');
  const captureUrl = new URL(`/${page}`, baseUrl);
  captureUrl.searchParams.set('case', scenario);
  for (const [key, value] of Object.entries(query)) captureUrl.searchParams.set(key, value);
  const args = [
    captureScript,
    '--url', captureUrl.href,
    '--surface', 'fixture',
    '--state', scenario,
    '--width', '800',
    '--height', '600',
    '--screenshot', screenshotPath,
    '--report', reportPath,
    '--manifest', manifestPath,
    '--timeout-ms', '10000',
  ];
  for (const selector of click) args.push('--click', selector);

  const requestCountBeforeCapture = rejectedRequestCount;
  const connectionCountBeforeCapture = rejectedConnectionCount;
  const datagramCountBeforeCapture = rejectedDatagramCount;
  const startedAt = Date.now();
  let failure;
  try {
    await execFileAsync(process.execPath, args, { maxBuffer: 10 * 1024 * 1024 });
  } catch (error) {
    failure = error;
  }
  if (query.kind?.includes('webtransport') || query.kind?.includes('webrtc')) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(failure, 'the request-boundary fixture unexpectedly captured successfully');
  assert.match(failure.stderr, /visual capture error: request boundary rejected/);
  assert.ok(failure.stderr.length <= 2_100, 'the request-boundary diagnostic was not bounded');
  assert.doesNotMatch(failure.stderr, /redirect-received|network-received|socket-received/);
  if (query.kind?.includes('webrtc')) {
    assert.ok(Date.now() - startedAt < 5_000, 'the WebRTC boundary did not fail promptly');
    assert.doesNotMatch(failure.stderr, /stun:|turns?:|127\.0\.0\.1:\d+/i);
  }
  assert.equal(rejectedConnectionCount, connectionCountBeforeCapture, 'Chromium connected to the rejected destination');
  assert.equal(rejectedRequestCount, requestCountBeforeCapture, 'the rejected destination received a request');
  assert.equal(rejectedDatagramCount, datagramCountBeforeCapture, 'Chromium sent traffic to the rejected WebTransport destination');
  await assert.rejects(access(screenshotPath));
  await assert.rejects(access(reportPath));
  await assert.rejects(access(manifestPath));
  return failure.stderr;
}

async function rejectedCapture(scenario, url) {
  const directory = path.join(artifactRoot, scenario);
  const screenshotPath = path.join(directory, 'capture.png');
  const reportPath = path.join(directory, 'report.json');
  const manifestPath = path.join(directory, 'manifest.json');
  const args = [
    captureScript,
    '--url', url,
    '--surface', 'fixture',
    '--state', scenario,
    '--width', '800',
    '--height', '600',
    '--screenshot', screenshotPath,
    '--report', reportPath,
    '--manifest', manifestPath,
  ];
  await assert.rejects(
    execFileAsync(process.execPath, args),
    (error) => error.code !== 0,
  );
  await assert.rejects(access(screenshotPath));
  await assert.rejects(access(reportPath));
  await assert.rejects(access(manifestPath));
}

test('reports fully, mostly, and centrally covered controls', async (testContext) => {
  for (const scenario of ['all', 'most', 'center']) {
    await testContext.test(scenario, async () => {
      const result = await capture(scenario);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /unreachable controls/);
      assert.equal(result.report.geometry.unreachable_controls.length, 1);
      assert.equal(result.report.geometry.unreachable_controls[0].tag, 'button');
    });
  }
});

test('allows a harmless edge obstruction and meaningful visible partial area', async (testContext) => {
  for (const scenario of ['edge', 'partial']) {
    await testContext.test(scenario, async () => {
      const result = await capture(scenario);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(result.report.geometry.unreachable_controls, []);
    });
  }
});

test('treats associated labels and native choice controls as reachable', async (testContext) => {
  for (const scenario of ['label', 'choice']) {
    await testContext.test(scenario, async () => {
      const result = await capture(scenario);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(result.report.geometry.unreachable_controls, []);
      assert.equal(result.report.geometry.choice_controls.length, 1);
    });
  }
});

test('treats nested icon and text descendants as part of their control', async () => {
  const result = await capture('nested-child');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.report.geometry.unreachable_controls, []);
});

test('measures a wrapped inline link by its clickable line fragments', async () => {
  const result = await capture('wrapped-inline-link', { width: 320 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.geometry.interactive_control_count, 1);
  assert.deepEqual(result.report.geometry.unreachable_controls, []);
});

test('reports a wrapped inline link when an actual line fragment is blocked', async () => {
  const result = await capture('wrapped-inline-link-blocked', { width: 320 });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unreachable controls/);
  assert.equal(result.report.geometry.unreachable_controls.length, 1);
  assert.equal(result.report.geometry.unreachable_controls[0].tag, 'a');
  assert.equal(result.report.geometry.unreachable_controls[0].center_reachable, false);
});

test('evaluates every supported native control and explicit interactive role', async () => {
  const result = await capture('control-types');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.geometry.interactive_control_count, 9);
  assert.deepEqual(result.report.geometry.unreachable_controls, []);
});

test('reports controls behind fixed consent and dialog overlays without flagging overlay actions', async (testContext) => {
  for (const scenario of ['consent', 'dialog']) {
    await testContext.test(scenario, async () => {
      const result = await capture(scenario);
      assert.notEqual(result.status, 0);
      assert.equal(result.report.geometry.unreachable_controls.length, 1);
      assert.ok(result.report.geometry.unreachable_controls[0].blockers.some((blocker) => blocker.position === 'fixed'));
    });
  }
});

test('catches the banner/input geometry that clipping and overflow metrics miss', async () => {
  const result = await capture('cloud-banner', { width: 1440, height: 900 });
  assert.notEqual(result.status, 0);
  assert.equal(result.report.geometry.horizontal_overflow, false);
  assert.deepEqual(result.report.geometry.clipped_text, []);
  assert.deepEqual(result.report.geometry.clipped_control_text, []);
  assert.equal(result.report.geometry.unreachable_controls.length, 1);
  assert.equal(result.report.geometry.unreachable_controls[0].name, 'organization_website');
});

test('waits for click navigation, fonts, and layout settling before capture', async () => {
  const result = await capture('navigation', {
    click: ['#deny-consent'],
    height: 844,
    page: 'navigate.html',
    width: 320,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.title, 'Settled API reference');
  assert.equal(result.report.settling.fonts_ready, true);
  assert.equal(result.report.settling.stable_for_ms, 1_000);
  assert.equal(result.report.geometry.document_width, 320);
  assert.equal(result.report.geometry.interactive_control_count, 2);
  assert.deepEqual(result.report.runtime, {
    playwright_core_version: '1.55.0',
    chromium_revision: '1187',
    chromium_version: '140.0.7339.16',
    chromium_package_version: '140.0.0',
    actual_browser_version: '140.0.7339.0',
  });
});

test('blocks redirects, navigations, frames, resources, fetches, and persistent connections before requests leave Chromium', async (testContext) => {
  const cases = [
    {
      name: 'initial redirect',
      page: 'initial-redirect',
      diagnostic: /cross-origin loopback destination for main-frame navigation/,
    },
    {
      name: 'credential-bearing redirect',
      page: 'target-redirect',
      query: { target: rejectedBaseUrl.replace('http://', 'http://user:password@') + '/credential-received' },
      diagnostic: /credential-bearing destination for main-frame navigation/,
    },
    {
      name: 'private redirect',
      page: 'target-redirect',
      query: { target: 'http://10.0.0.1/private-received' },
      diagnostic: /private destination for main-frame navigation/,
    },
    {
      name: 'link-local redirect',
      page: 'target-redirect',
      query: { target: 'http://169.254.169.254/link-local-received' },
      diagnostic: /link-local destination for main-frame navigation/,
    },
    {
      name: 'external redirect',
      page: 'target-redirect',
      query: { target: 'https://example.com/external-received' },
      diagnostic: /external destination for main-frame navigation/,
    },
    {
      name: 'post-click navigation',
      page: 'post-click-navigation.html',
      click: ['#leave'],
      query: { target: `${rejectedBaseUrl}/navigation-received` },
      diagnostic: /cross-origin loopback destination for main-frame navigation/,
    },
    {
      name: 'meta navigation',
      page: 'meta-navigation.html',
      query: { target: `${rejectedBaseUrl}/meta-received` },
      diagnostic: /cross-origin loopback destination for main-frame navigation/,
    },
    {
      name: 'form submission navigation',
      page: 'post-click-navigation.html',
      click: ['#submit'],
      query: { target: `${rejectedBaseUrl}/form-received` },
      diagnostic: /cross-origin loopback destination for main-frame navigation/,
    },
    {
      name: 'popup navigation',
      page: 'post-click-navigation.html',
      click: ['#popup'],
      query: { target: `${rejectedBaseUrl}/popup-received` },
      diagnostic: /cross-origin loopback destination for main-frame navigation/,
    },
    {
      name: 'nested frame',
      page: 'nested-frame.html',
      query: { target: `${rejectedBaseUrl}/frame-received` },
      diagnostic: /cross-origin loopback destination for frame navigation/,
    },
    {
      name: 'non-http frame',
      page: 'nested-frame.html',
      query: { target: 'data:text/html,disallowed-frame' },
      diagnostic: /non-http\(s\) destination for frame navigation/,
    },
    {
      name: 'local-file frame',
      page: 'nested-frame.html',
      query: { target: 'file:///etc/passwd' },
      diagnostic: /non-http\(s\) destination for frame navigation/,
    },
    {
      name: 'image subresource',
      page: 'network-request.html',
      query: { kind: 'image', target: `${rejectedBaseUrl}/network-received` },
      diagnostic: /cross-origin loopback destination for image resource/,
    },
    {
      name: 'fetch request',
      page: 'network-request.html',
      query: { kind: 'fetch', target: `${rejectedBaseUrl}/network-received` },
      diagnostic: /cross-origin loopback destination for fetch\/xhr request/,
    },
    {
      name: 'worker fetch request',
      page: 'network-request.html',
      query: { kind: 'worker-fetch', target: `${rejectedBaseUrl}/network-received` },
      diagnostic: /cross-origin loopback destination for fetch\/xhr request/,
    },
    {
      name: 'websocket connection',
      page: 'network-request.html',
      query: {
        kind: 'websocket',
        target: rejectedBaseUrl.replace(/^http:/, 'ws:') + '/socket-received',
      },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'webtransport connection',
      page: 'network-request.html',
      query: { kind: 'webtransport', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'webtransport constructor alias',
      page: 'network-request.html',
      query: { kind: 'webtransport-constructor-alias', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'worker webtransport connection',
      page: 'network-request.html',
      query: { kind: 'worker-webtransport', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'worker webtransport binding replacement',
      page: 'network-request.html',
      query: { kind: 'worker-webtransport-binding-replacement', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'worker webtransport relay replacement',
      page: 'network-request.html',
      query: { kind: 'worker-webtransport-relay-replacement', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'shared worker webtransport connection',
      page: 'network-request.html',
      query: { kind: 'shared-worker-webtransport', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'shared worker webtransport relay replacement',
      page: 'network-request.html',
      query: { kind: 'shared-worker-webtransport-relay-replacement', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'nested worker webtransport connection',
      page: 'network-request.html',
      query: { kind: 'nested-worker-webtransport', target: rejectedWebTransportUrl },
      diagnostic: /cross-origin loopback destination for persistent connection/,
    },
    {
      name: 'webrtc ICE connection',
      page: 'network-request.html',
      query: { kind: 'webrtc', target: rejectedWebRtcUrl },
      diagnostic: /cross-origin loopback destination for WebRTC persistent connection/,
    },
    {
      name: 'webrtc constructor alias',
      page: 'network-request.html',
      query: { kind: 'webrtc-constructor-alias', target: rejectedWebRtcUrl },
      diagnostic: /cross-origin loopback destination for WebRTC persistent connection/,
    },
    {
      name: 'webrtc frame constructor',
      page: 'network-request.html',
      query: { kind: 'webrtc-frame-constructor', target: rejectedWebRtcUrl },
      diagnostic: /cross-origin loopback destination for WebRTC persistent connection/,
    },
    {
      name: 'webrtc binding replacement',
      page: 'network-request.html',
      query: { kind: 'webrtc-binding-replacement', target: rejectedWebRtcUrl },
      diagnostic: /cross-origin loopback destination for WebRTC persistent connection/,
    },
    {
      name: 'webrtc TURN private destination',
      page: 'network-request.html',
      query: { kind: 'webrtc', target: 'turn:10.0.0.1:3478?transport=udp' },
      diagnostic: /private destination for WebRTC persistent connection/,
    },
    {
      name: 'webrtc TURN link-local destination',
      page: 'network-request.html',
      query: { kind: 'webrtc', target: 'turns:169.254.169.254:5349?transport=tcp' },
      diagnostic: /link-local destination for WebRTC persistent connection/,
    },
    {
      name: 'webrtc STUN external destination',
      page: 'network-request.html',
      query: { kind: 'webrtc', target: 'stun:example.com:3478' },
      diagnostic: /external destination for WebRTC persistent connection/,
    },
  ];

  for (const scenario of cases) {
    await testContext.test(scenario.name, async () => {
      const stderr = await boundaryRejectedCapture(`boundary-${scenario.name.replaceAll(' ', '-')}`, scenario);
      assert.match(stderr, scenario.diagnostic);
    });
  }
});

test('allows an asset from the exact capture origin', async () => {
  const requestsBeforeCapture = sameSurfaceAssetRequestCount;
  const result = await capture('allowed-same-surface-asset', { page: 'same-surface-asset.html' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(sameSurfaceAssetRequestCount, requestsBeforeCapture + 1);
  assert.equal(result.report.page_status, 200);
  assert.deepEqual(result.report.geometry.unreachable_controls, []);
});

test('allows a persistent connection to the exact capture origin', async () => {
  const connectionsBeforeCapture = sameSurfaceSocketCount;
  const result = await capture('allowed-same-surface-socket', {
    page: 'network-request.html',
    query: {
      kind: 'websocket',
      target: baseUrl.replace(/^http:/, 'ws:') + '/same-surface-socket',
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(sameSurfaceSocketCount, connectionsBeforeCapture + 1);
  assert.deepEqual(result.report.console_errors, []);
});

test('preserves dedicated and shared workers on an allowed surface', async (testContext) => {
  const workerKinds = [
    'worker-message',
    'module-worker-message',
    'shared-worker-message',
    'module-shared-worker-message',
  ];
  for (const kind of workerKinds) {
    await testContext.test(kind, async () => {
      const result = await capture(`allowed-${kind}`, {
        page: 'network-request.html',
        query: { kind },
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.report.title, 'Allowed same-surface worker');
      assert.deepEqual(result.report.console_errors, []);
    });
  }
});

test('preserves clipping, overflow, console, and native control-size failures', async (testContext) => {
  const cases = [
    ['horizontal-overflow', 'horizontal_overflow', true],
    ['clipped-text', 'clipped_text', 1],
    ['clipped-control', 'clipped_control_text', 1],
    ['console-error', 'console_errors', 1],
    ['oversized-choice', 'oversized_choice_controls', 1],
  ];
  for (const [scenario, field, expected] of cases) {
    await testContext.test(scenario, async () => {
      const result = await capture(scenario);
      assert.notEqual(result.status, 0);
      const findings = field === 'console_errors' ? result.report : result.report.geometry;
      assert.equal(Array.isArray(findings[field]) ? findings[field].length : findings[field], expected);
    });
  }
});

test('redacts control values and strips request query credentials from reports', async () => {
  const clipped = await capture('clipped-control');
  assert.equal(clipped.report.geometry.clipped_control_text[0].text, '[redacted]');
  assert.doesNotMatch(JSON.stringify(clipped.report.geometry.clipped_control_text), /sensitive-control-value/);

  const request = await capture('sanitized-request');
  assert.notEqual(request.status, 0);
  assert.ok(request.report.http_errors.some((entry) => entry.url.endsWith('/missing.png')));
  assert.doesNotMatch(JSON.stringify(request.report.http_errors), /must-not-appear/);
});

test('rejects unsafe URLs and preserves sanitized pre-report runtime errors', async () => {
  await rejectedCapture('host-rejected', 'https://example.com/');
  await rejectedCapture('credentials-rejected', 'http://user:password@localhost/');
  await assert.rejects(
    capture('missing-browser', {
      env: { PIPELINE_CHROMIUM_PATH: path.join(artifactRoot, 'missing-chromium') },
    }),
    (error) => {
      assert.match(error.message, /visual capture exited before writing its report/);
      assert.match(error.message, /configured Chromium executable is unavailable/);
      assert.doesNotMatch(error.message, /ENOENT|missing-chromium/);
      return true;
    },
  );
});
