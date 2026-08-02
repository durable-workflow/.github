import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
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
let baseUrl;

before(async () => {
  artifactRoot = await mkdtemp(path.join(os.tmpdir(), 'visual-capture-test-'));
  server = createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url, 'http://localhost').pathname;
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
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
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
  { click = [], env = {}, height = 600, page = 'occlusion.html', width = 800 } = {},
) {
  const directory = path.join(artifactRoot, scenario);
  const reportPath = path.join(directory, 'report.json');
  const args = [
    captureScript,
    '--url', `${baseUrl}/${page}${page.includes('?') ? '&' : '?'}case=${scenario}`,
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

async function rejectedCapture(scenario, url) {
  const directory = path.join(artifactRoot, scenario);
  const args = [
    captureScript,
    '--url', url,
    '--surface', 'fixture',
    '--state', scenario,
    '--width', '800',
    '--height', '600',
    '--screenshot', path.join(directory, 'capture.png'),
    '--report', path.join(directory, 'report.json'),
    '--manifest', path.join(directory, 'manifest.json'),
  ];
  await assert.rejects(
    execFileAsync(process.execPath, args),
    (error) => error.code !== 0,
  );
  await assert.rejects(access(path.join(directory, 'report.json')));
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
