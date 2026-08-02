#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const PUBLIC_SURFACE_HOSTS = new Set([
  'durable-workflow.com',
  'cloud.durable-workflow.com',
  'status.durable-workflow.com',
  'php.durable-workflow.com',
  'python.durable-workflow.com',
  'rust.durable-workflow.com',
]);
const CLICK_STABLE_WINDOW_MS = 1_000;
const DEFAULT_STABLE_WINDOW_MS = 250;
const EXPECTED_PLAYWRIGHT_CORE_VERSION = '1.55.0';
const EXPECTED_CHROMIUM_REVISION = '1187';
const EXPECTED_CHROMIUM_VERSION = '140.0.7339.16';
const EXPECTED_CHROMIUM_PACKAGE_VERSION = '140.0.0';

function loadChromium() {
  const runtimes = [
    ['playwright-core', '@sparticuz/chromium'],
    [
      '/opt/pipeline-visual/node_modules/playwright-core',
      '/opt/pipeline-visual/node_modules/@sparticuz/chromium',
    ],
  ];
  for (const [playwrightModuleName, chromiumModuleName] of runtimes) {
    try {
      const moduleRoot = path.dirname(require.resolve(playwrightModuleName));
      const packageMetadata = JSON.parse(fs.readFileSync(path.join(moduleRoot, 'package.json'), 'utf8'));
      const browserMetadata = JSON.parse(fs.readFileSync(path.join(moduleRoot, 'browsers.json'), 'utf8'));
      const chromiumMetadata = browserMetadata.browsers.find((browser) => browser.name === 'chromium');
      const chromiumModuleRoot = path.resolve(path.dirname(require.resolve(chromiumModuleName)), '..', '..');
      const chromiumPackageMetadata = JSON.parse(
        fs.readFileSync(path.join(chromiumModuleRoot, 'package.json'), 'utf8'),
      );
      if (
        packageMetadata.version !== EXPECTED_PLAYWRIGHT_CORE_VERSION
        || chromiumMetadata?.revision !== EXPECTED_CHROMIUM_REVISION
        || chromiumMetadata?.browserVersion !== EXPECTED_CHROMIUM_VERSION
        || chromiumPackageMetadata.version !== EXPECTED_CHROMIUM_PACKAGE_VERSION
      ) {
        throw new Error('the visual-capture Playwright and Chromium identities do not match the pinned runtime');
      }
      return {
        chromium: require(playwrightModuleName).chromium,
        chromiumRuntime: require(chromiumModuleName),
        identity: {
          playwright_core_version: packageMetadata.version,
          chromium_revision: chromiumMetadata.revision,
          chromium_version: chromiumMetadata.browserVersion,
          chromium_package_version: chromiumPackageMetadata.version,
        },
      };
    } catch (error) {
      if (error?.code !== 'MODULE_NOT_FOUND') throw error;
    }
  }
  throw new Error('playwright-core is required; run npm ci before using visual capture');
}

function isExecutable(candidate) {
  try {
    fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function chromiumExecutable(chromium, chromiumRuntime) {
  if (process.env.PIPELINE_CHROMIUM_PATH) {
    if (isExecutable(process.env.PIPELINE_CHROMIUM_PATH)) return process.env.PIPELINE_CHROMIUM_PATH;
    throw new Error('the configured Chromium executable is unavailable');
  }
  const candidates = [
    await chromiumRuntime.executablePath(),
    chromium.executablePath(),
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
  ];
  const executable = candidates.find(isExecutable);
  if (!executable) {
    throw new Error('the pinned npm Chromium runtime is unavailable');
  }
  return executable;
}

function sanitizeFailure(error) {
  const withoutControlCharacters = String(error?.message || error || 'unknown visual capture failure')
    .replace(/\u001b\[[0-9;]*m/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  return withoutControlCharacters.replace(/https?:\/\/[^\s)]+/g, (candidate) => {
    try {
      const url = new URL(candidate);
      return `${url.origin}${url.pathname}`;
    } catch {
      return '[redacted-url]';
    }
  }).slice(0, 2_000);
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const options = {
    width: 1440,
    height: 900,
    fullPage: false,
    timeoutMs: 30_000,
    state: 'default',
    click: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--full-page') {
      options.fullPage = true;
      continue;
    }
    if (argument === '--click') {
      const selector = argv[index + 1];
      if (!selector || selector.startsWith('--')) fail('--click requires a CSS selector');
      if (selector.length > 500) fail('--click selectors must not exceed 500 characters');
      options.click.push(selector);
      index += 1;
      continue;
    }
    if (!argument.startsWith('--')) fail(`unexpected argument: ${argument}`);
    const key = argument.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) fail(`${argument} requires a value`);
    options[key] = value;
    index += 1;
  }
  for (const key of ['url', 'surface', 'screenshot', 'report', 'manifest']) {
    if (!String(options[key] || '').trim()) {
      fail(`--${key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)} is required`);
    }
  }
  options.width = Number.parseInt(String(options.width), 10);
  options.height = Number.parseInt(String(options.height), 10);
  options.timeoutMs = Number.parseInt(String(options.timeoutMs), 10);
  if (!Number.isInteger(options.width) || options.width < 320 || options.width > 2560) {
    fail('--width must be between 320 and 2560');
  }
  if (!Number.isInteger(options.height) || options.height < 480 || options.height > 2400) {
    fail('--height must be between 480 and 2400');
  }
  if (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1_000 || options.timeoutMs > 120_000) {
    fail('--timeout-ms must be between 1000 and 120000');
  }
  return options;
}

function assertAllowedSurface(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    fail('--url must be an absolute URL');
  }
  const localHosts = new Set(['127.0.0.1', 'localhost', '[::1]']);
  const localPreview = ['http:', 'https:'].includes(parsed.protocol) && localHosts.has(parsed.hostname);
  const publicSurface = parsed.protocol === 'https:' && PUBLIC_SURFACE_HOSTS.has(parsed.hostname);
  if (!localPreview && !publicSurface) {
    fail('visual capture accepts only loopback previews or allowlisted Durable Workflow HTTPS surfaces');
  }
  if (parsed.username || parsed.password) fail('visual capture URLs must not contain credentials');
  return parsed;
}

function ensureOutputPath(filePath) {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  return resolved;
}

function relativeArtifactPath(manifestPath, artifactPath) {
  const manifestDirectory = path.dirname(manifestPath);
  const relative = path.relative(manifestDirectory, artifactPath).replaceAll(path.sep, '/');
  if (!relative || relative.startsWith('../') || path.isAbsolute(relative)) {
    fail('screenshot and report must be inside the manifest directory');
  }
  return relative;
}

function updateManifest(options, screenshotPath, reportPath, report) {
  const manifestPath = ensureOutputPath(options.manifest);
  let manifest = { schema: 'durable-workflow.pipeline.visual-review/v1', captures: [] };
  if (fs.existsSync(manifestPath)) {
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch {
      fail('existing visual manifest is not valid JSON');
    }
  }
  if (manifest.schema !== 'durable-workflow.pipeline.visual-review/v1' || !Array.isArray(manifest.captures)) {
    fail('existing visual manifest has an unsupported schema');
  }
  const capture = {
    surface: String(options.surface).trim(),
    state: String(options.state || 'default').trim() || 'default',
    viewport: { width: options.width, height: options.height },
    full_page: options.fullPage,
    screenshot: relativeArtifactPath(manifestPath, screenshotPath),
    report: relativeArtifactPath(manifestPath, reportPath),
    page_status: report.page_status,
    interactions: report.interactions,
  };
  manifest.captures = manifest.captures.filter((candidate) => !(
    candidate.surface === capture.surface
      && candidate.state === capture.state
      && candidate.viewport?.width === capture.viewport.width
      && candidate.viewport?.height === capture.viewport.height
      && Boolean(candidate.full_page) === capture.full_page
  ));
  manifest.captures.push(capture);
  manifest.generated_at = new Date().toISOString();
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

async function waitForFontsAndFrames(page) {
  await page.evaluate(async () => {
    if (document.fonts?.ready) await document.fonts.ready;
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}

async function layoutSignature(page, navigationCount) {
  return page.evaluate((observedNavigationCount) => {
    const rounded = (value) => Math.round(value * 10) / 10;
    const landmarks = [...document.querySelectorAll('body *')]
      .filter((element) => {
        const style = getComputedStyle(element);
        const box = element.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' && box.width > 0 && box.height > 0;
      })
      .slice(0, 1_000)
      .map((element) => {
        const box = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return [
          element.tagName,
          rounded(box.x),
          rounded(box.y),
          rounded(box.width),
          rounded(box.height),
          style.opacity,
          style.transform,
        ];
      });
    const finiteAnimations = document.getAnimations({ subtree: true })
      .filter((animation) => {
        const timing = animation.effect?.getComputedTiming();
        return ['pending', 'running'].includes(animation.playState) && Number.isFinite(timing?.endTime);
      })
      .map((animation) => [animation.playState, rounded(Number(animation.currentTime) || 0)]);
    return JSON.stringify({
      navigation_count: observedNavigationCount,
      url: location.href,
      ready_state: document.readyState,
      fonts_status: document.fonts?.status || 'unsupported',
      document_width: document.documentElement.scrollWidth,
      document_height: document.documentElement.scrollHeight,
      scroll_x: rounded(window.scrollX),
      scroll_y: rounded(window.scrollY),
      body_text_length: document.body?.innerText?.length || 0,
      finite_animations: finiteAnimations,
      landmarks,
    });
  }, navigationCount);
}

async function settlePage(page, timeoutMs, stableWindowMs, navigationState) {
  const deadline = Date.now() + timeoutMs;
  let observedNavigationCount = -1;
  let previousSignature = null;
  let stableSince = Date.now();

  while (Date.now() < deadline) {
    const remaining = Math.max(1, deadline - Date.now());
    try {
      await page.waitForLoadState('domcontentloaded', { timeout: remaining });
      if (observedNavigationCount !== navigationState.count) {
        await page.waitForLoadState('networkidle', { timeout: Math.max(1, deadline - Date.now()) });
        observedNavigationCount = navigationState.count;
        previousSignature = null;
      }
      await waitForFontsAndFrames(page);
      const signature = await layoutSignature(page, navigationState.count);
      if (signature !== previousSignature) {
        previousSignature = signature;
        stableSince = Date.now();
      } else if (Date.now() - stableSince >= stableWindowMs) {
        return {
          fonts_ready: await page.evaluate(() => !document.fonts || document.fonts.status === 'loaded'),
          stable_for_ms: stableWindowMs,
          navigation_events: navigationState.count,
        };
      }
    } catch (error) {
      if (Date.now() >= deadline) throw error;
      previousSignature = null;
      observedNavigationCount = -1;
    }
    await page.waitForTimeout(100);
  }
  throw new Error(`page did not reach a stable layout within ${timeoutMs}ms`);
}

function collectGeometry() {
  const round = (value) => Math.round(value * 100) / 100;
  const viewport = { left: 0, top: 0, right: window.innerWidth, bottom: window.innerHeight };
  const intersect = (first, second) => ({
    left: Math.max(first.left, second.left),
    top: Math.max(first.top, second.top),
    right: Math.min(first.right, second.right),
    bottom: Math.min(first.bottom, second.bottom),
  });
  const hasArea = (box) => box.right - box.left > 0.5 && box.bottom - box.top > 0.5;
  const visible = (element) => {
    const style = getComputedStyle(element);
    const box = element.getBoundingClientRect();
    if (style.visibility === 'hidden' || style.display === 'none' || Number.parseFloat(style.opacity) <= 0) return false;
    if (box.width <= 0 || box.height <= 0 || !element.getClientRects().length) return false;
    if (typeof element.checkVisibility === 'function') {
      return element.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true });
    }
    return true;
  };
  const visibleBox = (element) => {
    let box = intersect(element.getBoundingClientRect(), viewport);
    for (
      let ancestor = element.parentElement;
      ancestor && ancestor !== document.body && ancestor !== document.documentElement && hasArea(box);
      ancestor = ancestor.parentElement
    ) {
      const style = getComputedStyle(ancestor);
      const clipsX = ['auto', 'hidden', 'clip', 'scroll'].includes(style.overflowX);
      const clipsY = ['auto', 'hidden', 'clip', 'scroll'].includes(style.overflowY);
      if (!clipsX && !clipsY) continue;
      const ancestorBox = ancestor.getBoundingClientRect();
      box = {
        left: clipsX ? Math.max(box.left, ancestorBox.left) : box.left,
        right: clipsX ? Math.min(box.right, ancestorBox.right) : box.right,
        top: clipsY ? Math.max(box.top, ancestorBox.top) : box.top,
        bottom: clipsY ? Math.min(box.bottom, ancestorBox.bottom) : box.bottom,
      };
    }
    return box;
  };
  const controls = [...document.querySelectorAll('input[type="radio"], input[type="checkbox"]')]
    .filter(visible)
    .map((element) => {
      const box = element.getBoundingClientRect();
      return {
        type: element.getAttribute('type'),
        name: element.getAttribute('name') || '',
        width: round(box.width),
        height: round(box.height),
      };
    });
  const clippedText = [...document.querySelectorAll('body *')]
    .filter((element) => {
      if (!visible(element) || element.children.length > 0 || !element.textContent?.trim()) return false;
      const style = getComputedStyle(element);
      if (!['hidden', 'clip'].includes(style.overflowX) && !['hidden', 'clip'].includes(style.overflowY)) return false;
      return element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1;
    })
    .slice(0, 25)
    .map((element) => ({
      tag: element.tagName.toLowerCase(),
      text: element.textContent.trim().slice(0, 120),
    }));
  const textWidth = (text, style) => {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    if (!context) return 0;
    context.font = style.font || `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
    const letterSpacing = Number.parseFloat(style.letterSpacing) || 0;
    return context.measureText(text).width + Math.max(0, text.length - 1) * letterSpacing;
  };
  const clippedControlText = [...document.querySelectorAll('input, select')]
    .filter(visible)
    .flatMap((element) => {
      const style = getComputedStyle(element);
      const tag = element.tagName.toLowerCase();
      const type = String(element.getAttribute('type') || '').toLowerCase();
      if (tag === 'input' && !['', 'email', 'number', 'password', 'search', 'tel', 'text', 'url'].includes(type)) {
        return [];
      }

      const isSelect = tag === 'select';
      const placeholder = tag === 'input' ? String(element.getAttribute('placeholder') || '') : '';
      const value = isSelect
        ? String(element.selectedOptions?.[0]?.textContent || '').trim()
        : String(element.value || placeholder);
      if (!value) return [];

      const padding = (Number.parseFloat(style.paddingLeft) || 0) + (Number.parseFloat(style.paddingRight) || 0);
      const nativeSelectAllowance = isSelect && style.appearance !== 'none' ? 24 : 0;
      const availableWidth = Math.max(0, element.clientWidth - padding - nativeSelectAllowance);
      const measuredWidth = textWidth(value, style);
      if (measuredWidth <= availableWidth + 1) return [];

      const source = isSelect ? 'selected-option' : (element.value ? 'value' : 'placeholder');
      return [{
        tag,
        type: type || null,
        name: element.getAttribute('name') || '',
        source,
        text: source === 'value' || type === 'password' ? '[redacted]' : value.slice(0, 120),
        text_length: value.length,
        measured_width: round(measuredWidth),
        available_width: round(availableWidth),
      }];
    })
    .slice(0, 25);

  const interactiveRoles = new Set([
    'button', 'checkbox', 'combobox', 'link', 'menuitem', 'menuitemcheckbox', 'menuitemradio',
    'gridcell', 'option', 'radio', 'scrollbar', 'searchbox', 'slider', 'spinbutton', 'switch', 'tab',
    'textbox', 'treeitem',
  ]);
  const nativeInteractiveSelector = 'input, select, textarea, button, a[href], summary';
  const interactiveElements = [...document.querySelectorAll(`${nativeInteractiveSelector}, [role]`)]
    .filter((element) => {
      if (!visible(element)) return false;
      if (element.matches('input[type="hidden"], :disabled, [aria-disabled="true"]')) return false;
      if (element.closest('[aria-disabled="true"]')) return false;
      if (element.closest('[inert]')) return false;
      if (element.matches(nativeInteractiveSelector)) return true;
      const roles = String(element.getAttribute('role') || '').toLowerCase().split(/\s+/);
      return roles.some((role) => interactiveRoles.has(role));
    });
  const isRelatedHit = (hit, control) => {
    if (!hit) return false;
    if (hit === control || control.contains(hit)) return true;
    const labels = [...(control.labels || [])];
    if (labels.some((label) => hit === label || label.contains(hit))) return true;
    const hitLabel = hit.closest?.('label');
    return Boolean(hitLabel && hitLabel.control === control);
  };
  const describe = (element) => ({
    tag: element.tagName.toLowerCase(),
    type: element.getAttribute('type') || null,
    role: element.getAttribute('role') || null,
    name: element.getAttribute('name') || '',
  });
  const describeBlocker = (element) => {
    const style = getComputedStyle(element);
    return {
      tag: element.tagName.toLowerCase(),
      role: element.getAttribute('role') || null,
      position: style.position,
    };
  };
  const sampleFractions = [0.08, 0.29, 0.5, 0.71, 0.92];
  const unreachableControls = interactiveElements.flatMap((control) => {
    const controlBox = control.getBoundingClientRect();
    const box = visibleBox(control);
    if (!hasArea(box)) return [];
    const points = [];
    const seen = new Set();
    for (const yFraction of sampleFractions) {
      for (const xFraction of sampleFractions) {
        const x = Math.min(box.right - 0.01, box.left + (box.right - box.left) * xFraction);
        const y = Math.min(box.bottom - 0.01, box.top + (box.bottom - box.top) * yFraction);
        const key = `${round(x)}:${round(y)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        points.push({ x, y, center: xFraction === 0.5 && yFraction === 0.5 });
      }
    }
    let reachablePoints = 0;
    let centerReachable = false;
    const blockerCounts = new Map();
    for (const point of points) {
      const primary = document.elementFromPoint(point.x, point.y);
      const stack = document.elementsFromPoint(point.x, point.y);
      const reachable = isRelatedHit(primary, control);
      if (reachable) {
        reachablePoints += 1;
        if (point.center) centerReachable = true;
        continue;
      }
      const blocker = stack.find((element) => !isRelatedHit(element, control));
      if (blocker) blockerCounts.set(blocker, (blockerCounts.get(blocker) || 0) + 1);
    }
    const reachableAreaRatio = points.length ? reachablePoints / points.length : 0;
    if (centerReachable && reachableAreaRatio >= 0.5) return [];
    const blockers = [...blockerCounts.entries()]
      .sort((first, second) => second[1] - first[1])
      .slice(0, 3)
      .map(([element, blockedPoints]) => ({ ...describeBlocker(element), blocked_points: blockedPoints }));
    return [{
      ...describe(control),
      rect: {
        x: round(controlBox.x),
        y: round(controlBox.y),
        width: round(controlBox.width),
        height: round(controlBox.height),
        visible_width: round(box.right - box.left),
        visible_height: round(box.bottom - box.top),
      },
      tested_points: points.length,
      reachable_points: reachablePoints,
      reachable_area_ratio: round(reachableAreaRatio),
      center_reachable: centerReachable,
      blockers,
    }];
  }).slice(0, 25);

  const bodyText = document.body?.innerText?.trim() || '';
  return {
    document_width: document.documentElement.scrollWidth,
    viewport_width: document.documentElement.clientWidth,
    horizontal_overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
    body_text_length: bodyText.length,
    visible_element_count: [...document.querySelectorAll('body *')].filter(visible).length,
    interactive_control_count: interactiveElements.length,
    choice_controls: controls,
    oversized_choice_controls: controls.filter((control) => control.width > 32 || control.height > 32),
    clipped_text: clippedText,
    clipped_control_text: clippedControlText,
    unreachable_controls: unreachableControls,
  };
}

function reportFailures(report) {
  const failures = [];
  const geometry = report.geometry;
  if (geometry.horizontal_overflow) failures.push('horizontal overflow');
  if (geometry.clipped_text.length) failures.push('clipped text');
  if (geometry.clipped_control_text.length) failures.push('clipped control text');
  if (geometry.oversized_choice_controls.length) failures.push('oversized choice controls');
  if (geometry.unreachable_controls.length) failures.push('unreachable controls');
  if (report.console_errors.length) failures.push('console errors');
  if (report.page_errors.length) failures.push('page errors');
  return failures;
}

async function launchChromium() {
  const { chromium, chromiumRuntime, identity: runtimeIdentity } = loadChromium();
  const browser = await chromium.launch({
    executablePath: await chromiumExecutable(chromium, chromiumRuntime),
    headless: true,
    chromiumSandbox: false,
    args: [...chromiumRuntime.args, '--disable-dev-shm-usage'],
  });
  return { browser, runtimeIdentity };
}

const options = parseArgs(process.argv.slice(2));
const previewUrl = assertAllowedSurface(options.url);
const screenshotPath = ensureOutputPath(options.screenshot);
const reportPath = ensureOutputPath(options.report);
const consoleErrors = [];
const consoleWarnings = [];
const pageErrors = [];
const requestFailures = [];
const httpErrors = [];
const navigationState = { count: 0 };
let mainResponse;

const { browser, runtimeIdentity } = await launchChromium()
  .catch((error) => fail(`visual capture error: ${sanitizeFailure(error)}`));

try {
  const context = await browser.newContext({
    viewport: { width: options.width, height: options.height },
    deviceScaleFactor: 1,
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
  });
  const page = await context.newPage();
  page.on('console', (message) => {
    const entry = { type: message.type(), text: message.text().slice(0, 1_000) };
    if (message.type() === 'error') consoleErrors.push(entry);
    if (message.type() === 'warning') consoleWarnings.push(entry);
  });
  page.on('pageerror', (error) => pageErrors.push(String(error?.message || error).slice(0, 1_000)));
  page.on('requestfailed', (request) => requestFailures.push({
    url: request.url().split('?')[0].slice(0, 500),
    method: request.method(),
    error: String(request.failure()?.errorText || 'request failed').slice(0, 500),
  }));
  page.on('response', (pageResponse) => {
    if (pageResponse.request().isNavigationRequest() && pageResponse.frame() === page.mainFrame()) {
      mainResponse = pageResponse;
    }
    if (pageResponse.status() < 400) return;
    httpErrors.push({
      url: pageResponse.url().split('?')[0].slice(0, 500),
      status: pageResponse.status(),
      resource_type: pageResponse.request().resourceType(),
    });
  });
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigationState.count += 1;
  });

  mainResponse = await page.goto(previewUrl.href, {
    waitUntil: 'networkidle',
    timeout: options.timeoutMs,
  });
  for (const selector of options.click) {
    await page.locator(selector).click({ timeout: options.timeoutMs });
    await settlePage(page, options.timeoutMs, CLICK_STABLE_WINDOW_MS, navigationState);
    assertAllowedSurface(page.url());
  }
  await page.evaluate(() => window.scrollTo(0, 0));
  const settling = await settlePage(
    page,
    options.timeoutMs,
    options.click.length ? CLICK_STABLE_WINDOW_MS : DEFAULT_STABLE_WINDOW_MS,
    navigationState,
  );
  assertAllowedSurface(page.url());
  await waitForFontsAndFrames(page);

  const geometry = await page.evaluate(collectGeometry);

  await page.screenshot({
    path: screenshotPath,
    fullPage: options.fullPage,
    animations: 'disabled',
    caret: 'hide',
  });

  const report = {
    schema: 'durable-workflow.pipeline.visual-capture/v1',
    captured_at: new Date().toISOString(),
    surface: String(options.surface).trim(),
    state: String(options.state || 'default').trim() || 'default',
    viewport: { width: options.width, height: options.height },
    full_page: options.fullPage,
    interactions: options.click.map((selector) => ({ type: 'click', selector })),
    page_status: mainResponse?.status() || 0,
    title: await page.title(),
    runtime: {
      ...runtimeIdentity,
      actual_browser_version: browser.version(),
    },
    settling,
    geometry,
    console_errors: consoleErrors,
    console_warnings: consoleWarnings,
    page_errors: pageErrors,
    request_failures: requestFailures,
    http_errors: httpErrors,
  };
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  updateManifest(options, screenshotPath, reportPath, report);
  process.stdout.write(`${JSON.stringify(report)}\n`);
  const failures = reportFailures(report);
  if (failures.length) {
    process.stderr.write(`visual capture failed: ${failures.join(', ')}\n`);
    process.exitCode = 1;
  }
} catch (error) {
  process.stderr.write(`visual capture error: ${sanitizeFailure(error)}\n`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
