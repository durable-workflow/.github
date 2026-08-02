#!/usr/bin/env node

import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
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
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);
const GOOGLE_FONT_STYLES = new Map([
  [
    'status.durable-workflow.com',
    ['Geist:wght@300;400;500;600;700', 'JetBrains Mono:wght@400;500;600'],
  ],
  [
    'python.durable-workflow.com',
    ['Roboto:300,300i,400,400i,700,700i|Roboto Mono:400,400i,700,700i'],
  ],
]);
const CLICK_STABLE_WINDOW_MS = 1_000;
const DEFAULT_STABLE_WINDOW_MS = 250;
const EXPECTED_PLAYWRIGHT_CORE_VERSION = '1.55.0';
const EXPECTED_CHROMIUM_REVISION = '1187';
const EXPECTED_CHROMIUM_VERSION = '140.0.7339.16';
const EXPECTED_CHROMIUM_PACKAGE_VERSION = '140.0.0';
const ACTIVE_PROXY_SOCKETS = Symbol('activeProxySockets');

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
  const localPreview = ['http:', 'https:'].includes(parsed.protocol) && LOOPBACK_HOSTS.has(parsed.hostname);
  const publicSurface = parsed.protocol === 'https:' && PUBLIC_SURFACE_HOSTS.has(parsed.hostname);
  if (!localPreview && !publicSurface) {
    fail('visual capture accepts only loopback previews or allowlisted Durable Workflow HTTPS surfaces');
  }
  if (parsed.username || parsed.password) fail('visual capture URLs must not contain credentials');
  return parsed;
}

function normalizedIpHostname(hostname) {
  const unwrapped = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
  const ipv4Mapped = unwrapped.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return ipv4Mapped ? ipv4Mapped[1] : unwrapped;
}

function destinationClass(hostname) {
  const normalized = normalizedIpHostname(hostname);
  if (LOOPBACK_HOSTS.has(hostname) || normalized === '::1') return 'cross-origin loopback destination';
  if (net.isIP(normalized) === 4) {
    const [first, second] = normalized.split('.').map(Number);
    if (first === 169 && second === 254) return 'link-local destination';
    if (
      first === 0
      || first === 10
      || first === 127
      || (first === 100 && second >= 64 && second <= 127)
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || first >= 224
    ) return 'private destination';
  }
  if (net.isIP(normalized) === 6) {
    const firstGroup = Number.parseInt(normalized.split(':', 1)[0] || '0', 16);
    if ((firstGroup & 0xffc0) === 0xfe80) return 'link-local destination';
    if ((firstGroup & 0xfe00) === 0xfc00 || normalized === '::') return 'private destination';
  }
  return 'external destination';
}

function allowedGoogleFontStyle(captureUrl, requestUrl, method, resourceType) {
  const expectedFamilies = GOOGLE_FONT_STYLES.get(captureUrl.hostname);
  if (
    !expectedFamilies
    || requestUrl.origin !== 'https://fonts.googleapis.com'
    || method !== 'GET'
    || resourceType !== 'stylesheet'
    || !['/css', '/css2'].includes(requestUrl.pathname)
  ) return false;

  const parameters = [...requestUrl.searchParams.keys()];
  const displays = requestUrl.searchParams.getAll('display');
  const families = requestUrl.searchParams.getAll('family');
  return parameters.length === expectedFamilies.length + 1
    && parameters.every((key) => ['display', 'family'].includes(key))
    && displays.length === 1
    && displays[0] === (requestUrl.pathname === '/css2' ? 'swap' : 'fallback')
    && JSON.stringify(families) === JSON.stringify(expectedFamilies);
}

function allowedGoogleFontFile(captureUrl, requestUrl, method, resourceType) {
  return GOOGLE_FONT_STYLES.has(captureUrl.hostname)
    && requestUrl.origin === 'https://fonts.gstatic.com'
    && method === 'GET'
    && resourceType === 'font'
    && requestUrl.search === ''
    && /^\/s\/[a-z0-9_-]+\/v\d+\/[a-zA-Z0-9_-]+\.woff2$/.test(requestUrl.pathname);
}

function allowedPublicAsset(captureUrl, requestUrl, method, resourceType) {
  if (
    captureUrl.hostname === 'durable-workflow.com'
    && requestUrl.origin === 'https://api.github.com'
    && requestUrl.pathname === '/repos/durable-workflow/workflow'
    && requestUrl.search === ''
    && method === 'GET'
    && ['fetch', 'xhr'].includes(resourceType)
  ) return true;
  return allowedGoogleFontStyle(captureUrl, requestUrl, method, resourceType)
    || allowedGoogleFontFile(captureUrl, requestUrl, method, resourceType);
}

function protocolRequestClass(resourceType, frameId, mainFrameId) {
  const normalized = String(resourceType || 'browser').toLowerCase();
  if (normalized === 'document') {
    return frameId === mainFrameId ? 'main-frame navigation' : 'frame navigation';
  }
  if (['fetch', 'xhr'].includes(normalized)) return 'fetch/xhr request';
  if (normalized === 'eventsource') return 'persistent connection';
  return `${normalized} resource`;
}

function routedRequestClass(request) {
  const resourceType = request.resourceType();
  if (resourceType === 'document') {
    try {
      return request.frame()?.parentFrame() ? 'frame navigation' : 'main-frame navigation';
    } catch {
      return 'main-frame navigation';
    }
  }
  if (['fetch', 'xhr'].includes(resourceType)) return 'fetch/xhr request';
  if (resourceType === 'eventsource') return 'persistent connection';
  return `${resourceType || 'browser'} resource`;
}

function rejectedDestination(captureUrl, rawUrl, method, resourceType) {
  let requestUrl;
  try {
    requestUrl = new URL(rawUrl);
  } catch {
    return 'invalid destination';
  }
  if (requestUrl.username || requestUrl.password) return 'credential-bearing destination';
  if (!['http:', 'https:'].includes(requestUrl.protocol)) return 'non-http(s) destination';
  if (requestUrl.origin === captureUrl.origin) return null;
  if (allowedPublicAsset(captureUrl, requestUrl, method, resourceType)) return null;
  return destinationClass(requestUrl.hostname);
}

function rejectedPersistentDestination(captureUrl, rawUrl) {
  let requestUrl;
  try {
    requestUrl = new URL(rawUrl);
  } catch {
    return 'invalid destination';
  }
  if (requestUrl.username || requestUrl.password) return 'credential-bearing destination';
  if (!['ws:', 'wss:'].includes(requestUrl.protocol)) return 'non-http(s) destination';
  requestUrl.protocol = requestUrl.protocol === 'ws:' ? 'http:' : 'https:';
  if (requestUrl.origin === captureUrl.origin) return null;
  return destinationClass(requestUrl.hostname);
}

function rejectedWebRtcDestination(rawUrl) {
  const match = String(rawUrl || '').match(
    /^(?:stun|stuns|turn|turns):(?:\/\/)?(\[[^\]]+\]|[^:/?#]+)(?::\d+)?(?:\?[^#]*)?$/i,
  );
  if (!match) return 'unapproved direct transport destination';
  return destinationClass(match[1]);
}

function allowedProxyOrigin(captureUrl, requestUrl) {
  if (requestUrl.origin === captureUrl.origin) return true;
  if (
    captureUrl.hostname === 'durable-workflow.com'
    && requestUrl.origin === 'https://api.github.com'
  ) return true;
  return GOOGLE_FONT_STYLES.has(captureUrl.hostname)
    && ['https://fonts.googleapis.com', 'https://fonts.gstatic.com'].includes(requestUrl.origin);
}

function networkPort(url) {
  if (url.port) return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
}

function sameNetworkAuthority(firstUrl, secondUrl) {
  return normalizedIpHostname(firstUrl.hostname) === normalizedIpHostname(secondUrl.hostname)
    && networkPort(firstUrl) === networkPort(secondUrl);
}

function rejectedProxyDestination(captureUrl, rawUrl, allowCaptureAuthority = false) {
  let requestUrl;
  try {
    requestUrl = new URL(rawUrl);
  } catch {
    return 'invalid destination';
  }
  if (requestUrl.username || requestUrl.password) return 'credential-bearing destination';
  if (!['http:', 'https:'].includes(requestUrl.protocol)) return 'non-http(s) destination';
  if (allowedProxyOrigin(captureUrl, requestUrl)) return null;
  if (allowCaptureAuthority && sameNetworkAuthority(captureUrl, requestUrl)) return null;
  return destinationClass(requestUrl.hostname);
}

function proxyRequestUrl(request) {
  try {
    return new URL(request.url);
  } catch {
    return null;
  }
}

async function startBoundaryProxy(captureUrl, boundary) {
  const proxy = http.createServer((request, response) => {
    const requestUrl = proxyRequestUrl(request);
    const rejected = rejectedProxyDestination(captureUrl, requestUrl?.href || request.url);
    if (rejected) {
      boundary.reject(rejected, 'browser connection');
      response.writeHead(403, { connection: 'close' }).end();
      return;
    }

    const headers = { ...request.headers };
    delete headers['proxy-connection'];
    const transport = requestUrl.protocol === 'https:' ? https : http;
    const outgoing = transport.request(requestUrl, {
      method: request.method,
      headers,
    }, (incoming) => {
      response.writeHead(incoming.statusCode || 502, incoming.headers);
      incoming.pipe(response);
    });
    outgoing.on('error', () => {
      if (!response.headersSent) response.writeHead(502, { connection: 'close' });
      response.end();
    });
    request.pipe(outgoing);
  });

  proxy.on('connect', (request, browserSocket, head) => {
    const authorityUrl = (() => {
      try {
        return new URL(`https://${request.url}`);
      } catch {
        return null;
      }
    })();
    const rejected = rejectedProxyDestination(
      captureUrl,
      authorityUrl?.href || request.url,
      true,
    );
    if (rejected) {
      boundary.reject(rejected, 'browser connection');
      browserSocket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }

    let tunnelEstablished = false;
    const destinationSocket = net.connect({
      host: normalizedIpHostname(authorityUrl.hostname),
      port: Number(authorityUrl.port || 443),
    });
    destinationSocket.once('connect', () => {
      tunnelEstablished = true;
      browserSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) destinationSocket.write(head);
      destinationSocket.pipe(browserSocket);
      browserSocket.pipe(destinationSocket);
    });
    destinationSocket.once('error', () => {
      if (!tunnelEstablished) {
        browserSocket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
      } else {
        browserSocket.destroy();
      }
    });
    browserSocket.once('error', () => destinationSocket.destroy());
    browserSocket.once('close', () => destinationSocket.destroy());
  });
  proxy.on('clientError', (_error, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });
  const activeSockets = new Set();
  proxy[ACTIVE_PROXY_SOCKETS] = activeSockets;
  proxy.on('connection', (socket) => {
    activeSockets.add(socket);
    socket.once('close', () => activeSockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    proxy.once('error', reject);
    proxy.listen(0, '127.0.0.1', resolve);
  });
  return proxy;
}

function closeServer(server) {
  for (const socket of server[ACTIVE_PROXY_SOCKETS] || []) socket.destroy();
  return new Promise((resolve) => server.close(() => resolve()));
}

function installPersistentConnectionBoundary({ bindingName, captureOrigin }) {
  const trustedBoundarySignal = globalThis[bindingName];
  const signalRejection = (transport, rawUrl) => {
    try {
      const signal = trustedBoundarySignal({ transport, url: rawUrl });
      void signal?.catch?.(() => {});
    } catch {
      // Chromium's network policy remains fail-closed if the diagnostic channel is unavailable.
    }
  };
  const replacePrototypeConstructor = (NativeConstructor, GuardedConstructor) => {
    const constructorDescriptor = Object.getOwnPropertyDescriptor(
      NativeConstructor.prototype,
      'constructor',
    );
    Object.defineProperty(NativeConstructor.prototype, 'constructor', {
      ...constructorDescriptor,
      value: GuardedConstructor,
    });
  };

  const NativeWebTransport = globalThis.WebTransport;
  if (typeof NativeWebTransport === 'function') {
    const GuardedWebTransport = new Proxy(NativeWebTransport, {
      construct(target, argumentsList, newTarget) {
        let rawUrl = '';
        let allowed = false;
        try {
          rawUrl = String(argumentsList[0]);
          const destination = new URL(rawUrl, globalThis.location?.href);
          allowed = destination.protocol === 'https:'
            && !destination.username
            && !destination.password
            && destination.origin === captureOrigin;
        } catch {
          // The browser-side guard reports malformed destinations to the trusted process below.
        }
        if (!allowed) {
          signalRejection('webtransport', rawUrl);
          throw new DOMException('Blocked by visual capture request policy', 'SecurityError');
        }
        return Reflect.construct(target, argumentsList, newTarget);
      },
    });
    replacePrototypeConstructor(NativeWebTransport, GuardedWebTransport);
    globalThis.WebTransport = GuardedWebTransport;
  }

  const guardedPeerConnectionConstructors = new Map();
  for (const constructorName of ['RTCPeerConnection', 'webkitRTCPeerConnection']) {
    const NativePeerConnection = globalThis[constructorName];
    if (typeof NativePeerConnection !== 'function') continue;
    let GuardedPeerConnection = guardedPeerConnectionConstructors.get(NativePeerConnection);
    if (!GuardedPeerConnection) {
      GuardedPeerConnection = new Proxy(NativePeerConnection, {
        construct(_target, argumentsList) {
          let iceServerUrl = '';
          try {
            const iceServers = argumentsList[0]?.iceServers || [];
            for (const iceServer of iceServers) {
              const urls = Array.isArray(iceServer?.urls) ? iceServer.urls : [iceServer?.urls];
              const configuredUrl = urls.find((candidate) => candidate !== undefined);
              if (configuredUrl !== undefined) {
                iceServerUrl = String(configuredUrl);
                break;
              }
            }
          } catch {
            // Reject malformed or accessor-backed configurations without invoking Chromium.
          }
          signalRejection('webrtc', iceServerUrl);
          throw new DOMException('Blocked by visual capture request policy', 'SecurityError');
        },
      });
      replacePrototypeConstructor(NativePeerConnection, GuardedPeerConnection);
      guardedPeerConnectionConstructors.set(NativePeerConnection, GuardedPeerConnection);
    }
    globalThis[constructorName] = GuardedPeerConnection;
  }
}

function installWorkerPersistentConnectionBoundary({ bindingName, captureOrigin, installerSource }) {
  const trustedBoundarySignal = globalThis[bindingName];
  const trustedApply = Reflect.apply;
  const trustedAddEventListener = EventTarget.prototype.addEventListener;
  const trustedStopImmediatePropagation = Event.prototype.stopImmediatePropagation;
  const trustedMessageData = Object.getOwnPropertyDescriptor(
    MessageEvent.prototype,
    'data',
  ).get;
  const trustedMessagePortStart = MessagePort.prototype.start;
  const marker = `pipeline-visual-capture-${crypto.randomUUID()}`;
  const boundaryArguments = JSON.stringify({ bindingName, captureOrigin });
  const workerBoundaryArguments = JSON.stringify({ bindingName, captureOrigin, installerSource });
  const workerInstallerSource = installWorkerPersistentConnectionBoundary.toString();
  const installChildBoundaries = [
    `(${installerSource})(${boundaryArguments});`,
    `(${workerInstallerSource})(${workerBoundaryArguments});`,
  ];
  const loadWorkerSource = (sourceUrl, options) => options.type === 'module'
    ? `import ${JSON.stringify(sourceUrl)};`
    : `importScripts(${JSON.stringify(sourceUrl)});`;
  const relayViolation = (connection) => {
    try {
      const signal = trustedBoundarySignal(connection);
      void signal?.catch?.(() => {});
    } catch {
      // The worker guard has already prevented the destination from receiving traffic.
    }
  };
  const handleBoundaryMessage = (event) => {
    const data = trustedApply(trustedMessageData, event, []);
    if (!data || typeof data !== 'object' || !(marker in data)) return;
    trustedApply(trustedStopImmediatePropagation, event, []);
    relayViolation(data[marker]);
  };
  const addBoundaryMessageListener = (target) => {
    trustedApply(
      trustedAddEventListener,
      target,
      ['message', handleBoundaryMessage, { capture: true }],
    );
  };
  const replacePrototypeConstructor = (NativeConstructor, GuardedConstructor) => {
    const constructorDescriptor = Object.getOwnPropertyDescriptor(
      NativeConstructor.prototype,
      'constructor',
    );
    Object.defineProperty(NativeConstructor.prototype, 'constructor', {
      ...constructorDescriptor,
      value: GuardedConstructor,
    });
  };

  const NativeWorker = globalThis.Worker;
  if (typeof NativeWorker === 'function') {
    const GuardedWorker = new Proxy(NativeWorker, {
      construct(target, argumentsList, newTarget) {
        const sourceUrl = new URL(String(argumentsList[0]), globalThis.location.href).href;
        const options = argumentsList[1] || {};
        const bootstrap = [
          `globalThis[${JSON.stringify(bindingName)}] = ((apply, postMessage, receiver) => {`,
          '  return (connection) => {',
          `    apply(postMessage, receiver, [{ ${JSON.stringify(marker)}: connection }]);`,
          '  };',
          '})(Reflect.apply, globalThis.postMessage, globalThis);',
          ...installChildBoundaries,
          loadWorkerSource(sourceUrl, options),
        ].join('\n');
        const bootstrapUrl = URL.createObjectURL(new Blob([bootstrap], { type: 'text/javascript' }));
        const worker = Reflect.construct(target, [bootstrapUrl, options], newTarget);
        addBoundaryMessageListener(worker);
        URL.revokeObjectURL(bootstrapUrl);
        return worker;
      },
    });
    replacePrototypeConstructor(NativeWorker, GuardedWorker);
    globalThis.Worker = GuardedWorker;
  }

  const NativeSharedWorker = globalThis.SharedWorker;
  if (typeof NativeSharedWorker === 'function') {
    const sharedBootstrapUrls = new Map();
    const trustedSharedWorkerPort = Object.getOwnPropertyDescriptor(
      NativeSharedWorker.prototype,
      'port',
    ).get;
    const GuardedSharedWorker = new Proxy(NativeSharedWorker, {
      construct(target, argumentsList, newTarget) {
        const sourceUrl = new URL(String(argumentsList[0]), globalThis.location.href).href;
        const rawOptions = argumentsList[1];
        const options = rawOptions && typeof rawOptions === 'object' ? rawOptions : {};
        const cacheKey = JSON.stringify([sourceUrl, options.type || 'classic']);
        let bootstrapUrl = sharedBootstrapUrls.get(cacheKey);
        if (!bootstrapUrl) {
          const bootstrap = [
            '((apply, addEventListener, arrayPush, messagePorts, postMessage, start, receiver) => {',
            '  const boundaryPorts = [];',
            '  const pendingBoundaryViolations = [];',
            `  globalThis[${JSON.stringify(bindingName)}] = (connection) => {`,
            '    if (!boundaryPorts.length) apply(arrayPush, pendingBoundaryViolations, [connection]);',
            '    for (let index = 0; index < boundaryPorts.length; index += 1) {',
            `      apply(postMessage, boundaryPorts[index], [{ ${JSON.stringify(marker)}: connection }]);`,
            '    }',
            '  };',
            "  apply(addEventListener, receiver, ['connect', (event) => {",
            '    const ports = apply(messagePorts, event, []);',
            '    for (let portIndex = 0; portIndex < ports.length; portIndex += 1) {',
            '      const port = ports[portIndex];',
            '      apply(arrayPush, boundaryPorts, [port]);',
            '      apply(start, port, []);',
            '      for (let index = 0; index < pendingBoundaryViolations.length; index += 1) {',
            `        apply(postMessage, port, [{ ${JSON.stringify(marker)}: pendingBoundaryViolations[index] }]);`,
            '      }',
            '    }',
            '    pendingBoundaryViolations.length = 0;',
            '  }]);',
            '})(',
            '  Reflect.apply,',
            '  globalThis.addEventListener,',
            '  Array.prototype.push,',
            "  Object.getOwnPropertyDescriptor(MessageEvent.prototype, 'ports').get,",
            '  MessagePort.prototype.postMessage,',
            '  MessagePort.prototype.start,',
            '  globalThis,',
            ');',
            ...installChildBoundaries,
            loadWorkerSource(sourceUrl, options),
          ].join('\n');
          bootstrapUrl = URL.createObjectURL(new Blob([bootstrap], { type: 'text/javascript' }));
          sharedBootstrapUrls.set(cacheKey, bootstrapUrl);
        }
        const sharedWorker = Reflect.construct(
          target,
          [bootstrapUrl, ...argumentsList.slice(1)],
          newTarget,
        );
        const port = trustedApply(trustedSharedWorkerPort, sharedWorker, []);
        addBoundaryMessageListener(port);
        trustedApply(trustedMessagePortStart, port, []);
        return sharedWorker;
      },
    });
    replacePrototypeConstructor(NativeSharedWorker, GuardedSharedWorker);
    globalThis.SharedWorker = GuardedSharedWorker;
  }
}

function requestBoundary(captureUrl) {
  let violation;
  let signalViolation;
  const signal = new Promise((resolve) => {
    signalViolation = resolve;
  });
  const reject = (destination, kind) => {
    if (violation) return;
    violation = { destination, kind };
    signalViolation(violation);
  };
  const error = () => new Error(
    `request boundary rejected a ${violation.destination} for ${violation.kind}`,
  );
  return {
    inspect(rawUrl, method, resourceType, kind) {
      const rejected = rejectedDestination(captureUrl, rawUrl, method, resourceType);
      if (rejected) reject(rejected, kind);
      return rejected;
    },
    reject,
    throwIfRejected() {
      if (violation) throw error();
    },
    async guard(operation) {
      const result = await Promise.race([
        operation,
        signal.then(() => { throw error(); }),
      ]);
      if (violation) throw error();
      return result;
    },
    violation() {
      return violation;
    },
  };
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
  const visibleFragments = (element) => {
    let clippingBox = viewport;
    for (
      let ancestor = element.parentElement;
      ancestor && ancestor !== document.body && ancestor !== document.documentElement && hasArea(clippingBox);
      ancestor = ancestor.parentElement
    ) {
      const style = getComputedStyle(ancestor);
      const clipsX = ['auto', 'hidden', 'clip', 'scroll'].includes(style.overflowX);
      const clipsY = ['auto', 'hidden', 'clip', 'scroll'].includes(style.overflowY);
      if (!clipsX && !clipsY) continue;
      const ancestorBox = ancestor.getBoundingClientRect();
      clippingBox = {
        left: clipsX ? Math.max(clippingBox.left, ancestorBox.left) : clippingBox.left,
        right: clipsX ? Math.min(clippingBox.right, ancestorBox.right) : clippingBox.right,
        top: clipsY ? Math.max(clippingBox.top, ancestorBox.top) : clippingBox.top,
        bottom: clipsY ? Math.min(clippingBox.bottom, ancestorBox.bottom) : clippingBox.bottom,
      };
    }
    return [...element.getClientRects()]
      .map((fragment) => intersect(fragment, clippingBox))
      .filter(hasArea);
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
    const fragments = visibleFragments(control);
    if (!fragments.length) return [];
    const box = {
      left: Math.min(...fragments.map((fragment) => fragment.left)),
      top: Math.min(...fragments.map((fragment) => fragment.top)),
      right: Math.max(...fragments.map((fragment) => fragment.right)),
      bottom: Math.max(...fragments.map((fragment) => fragment.bottom)),
    };
    const points = [];
    const seen = new Set();
    for (const fragment of fragments) {
      const fragmentArea = (fragment.right - fragment.left) * (fragment.bottom - fragment.top);
      const sampleArea = fragmentArea / (sampleFractions.length ** 2);
      for (const yFraction of sampleFractions) {
        for (const xFraction of sampleFractions) {
          const x = Math.min(
            fragment.right - 0.01,
            fragment.left + (fragment.right - fragment.left) * xFraction,
          );
          const y = Math.min(
            fragment.bottom - 0.01,
            fragment.top + (fragment.bottom - fragment.top) * yFraction,
          );
          const key = `${round(x)}:${round(y)}`;
          if (seen.has(key)) continue;
          seen.add(key);
          points.push({
            x,
            y,
            area: sampleArea,
            center: xFraction === 0.5 && yFraction === 0.5,
          });
        }
      }
    }
    let reachablePoints = 0;
    let reachableArea = 0;
    let centerReachable = true;
    const blockerCounts = new Map();
    for (const point of points) {
      const primary = document.elementFromPoint(point.x, point.y);
      const stack = document.elementsFromPoint(point.x, point.y);
      const reachable = isRelatedHit(primary, control);
      if (reachable) {
        reachablePoints += 1;
        reachableArea += point.area;
        continue;
      }
      if (point.center) centerReachable = false;
      const blocker = stack.find((element) => !isRelatedHit(element, control));
      if (blocker) blockerCounts.set(blocker, (blockerCounts.get(blocker) || 0) + 1);
    }
    const sampledArea = points.reduce((total, point) => total + point.area, 0);
    const reachableAreaRatio = sampledArea ? reachableArea / sampledArea : 0;
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

async function launchChromium(proxyPort) {
  const { chromium, chromiumRuntime, identity: runtimeIdentity } = loadChromium();
  const browser = await chromium.launch({
    executablePath: await chromiumExecutable(chromium, chromiumRuntime),
    headless: true,
    chromiumSandbox: false,
    args: [
      ...chromiumRuntime.args,
      '--disable-dev-shm-usage',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      `--proxy-server=http://127.0.0.1:${proxyPort}`,
      '--proxy-bypass-list=<-loopback>',
    ],
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
const boundary = requestBoundary(previewUrl);
let mainResponse;
let context;
let page;
const boundaryProxy = await startBoundaryProxy(previewUrl, boundary)
  .catch((error) => fail(`visual capture error: ${sanitizeFailure(error)}`));

const { browser, runtimeIdentity } = await launchChromium(boundaryProxy.address().port)
  .catch(async (error) => {
    await closeServer(boundaryProxy);
    fail(`visual capture error: ${sanitizeFailure(error)}`);
  });

try {
  context = await browser.newContext({
    viewport: { width: options.width, height: options.height },
    deviceScaleFactor: 1,
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
  });
  const persistentBoundaryBinding = '__pipelineVisualCaptureRejectPersistentConnection';
  await context.exposeBinding(persistentBoundaryBinding, (_source, connection) => {
    if (connection?.transport === 'webrtc') {
      boundary.reject(rejectedWebRtcDestination(connection.url), 'WebRTC persistent connection');
      return;
    }
    const rawUrl = connection?.transport === 'webtransport' ? connection.url : connection;
    const rejected = rejectedDestination(previewUrl, rawUrl, 'CONNECT', 'webtransport');
    if (rejected) boundary.reject(rejected, 'persistent connection');
  });
  await context.addInitScript(installPersistentConnectionBoundary, {
    bindingName: persistentBoundaryBinding,
    captureOrigin: previewUrl.origin,
  });
  await context.addInitScript(installWorkerPersistentConnectionBoundary, {
    bindingName: persistentBoundaryBinding,
    captureOrigin: previewUrl.origin,
    installerSource: installPersistentConnectionBoundary.toString(),
  });
  await context.route('**/*', async (route, request) => {
    const kind = routedRequestClass(request);
    const headers = request.headers();
    const credentialHeader = headers.authorization || headers['proxy-authorization'];
    let requestPage;
    try {
      requestPage = request.frame().page();
    } catch {
      requestPage = page;
    }
    if (credentialHeader) boundary.reject('credential-bearing request', kind);
    const rejected = credentialHeader
      || boundary.inspect(request.url(), request.method(), request.resourceType(), kind);
    if (!rejected && page && requestPage !== page) {
      boundary.reject('out-of-surface page destination', kind);
    }
    if (rejected || (page && requestPage !== page)) {
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
  await context.routeWebSocket(/.*/, async (webSocket) => {
    const rejected = rejectedPersistentDestination(previewUrl, webSocket.url());
    if (rejected) {
      boundary.reject(rejected, 'persistent connection');
      await webSocket.close({ code: 1008, reason: 'blocked by visual capture policy' });
      return;
    }
    webSocket.connectToServer();
  });
  context.on('page', (openedPage) => {
    if (page && openedPage !== page) {
      boundary.reject('out-of-surface page destination', 'main-frame navigation');
    }
    const initialUrl = openedPage.url();
    if (!['about:blank', 'about:srcdoc'].includes(initialUrl)) {
      boundary.inspect(initialUrl, 'GET', 'document', 'main-frame navigation');
    }
    openedPage.on('framenavigated', (frame) => {
      const frameUrl = frame.url();
      if (['about:blank', 'about:srcdoc'].includes(frameUrl)) return;
      const kind = frame.parentFrame() ? 'frame navigation' : 'main-frame navigation';
      boundary.inspect(frameUrl, 'GET', 'document', kind);
    });
  });
  page = await context.newPage();
  const protocol = await context.newCDPSession(page);
  const frameTree = await protocol.send('Page.getFrameTree');
  const mainFrameId = frameTree.frameTree.frame.id;
  const inspectNavigation = (event) => {
    const kind = event.frameId === mainFrameId ? 'main-frame navigation' : 'frame navigation';
    boundary.inspect(event.url, 'GET', 'document', kind);
  };
  protocol.on('Page.frameRequestedNavigation', inspectNavigation);
  protocol.on('Page.frameScheduledNavigation', inspectNavigation);
  protocol.on('Page.frameStartedNavigating', inspectNavigation);
  protocol.on('Fetch.requestPaused', (event) => {
    const handleRequest = async () => {
      const resourceType = String(event.resourceType || 'browser').toLowerCase();
      const kind = protocolRequestClass(resourceType, event.frameId, mainFrameId);
      const headers = event.request.headers || {};
      const credentialHeader = headers.Authorization
        || headers.authorization
        || headers['Proxy-Authorization']
        || headers['proxy-authorization'];
      if (credentialHeader) boundary.reject('credential-bearing request', kind);
      const rejected = credentialHeader
        || boundary.inspect(event.request.url, event.request.method, resourceType, kind);
      await protocol.send(
        rejected ? 'Fetch.failRequest' : 'Fetch.continueRequest',
        rejected
          ? { requestId: event.requestId, errorReason: 'BlockedByClient' }
          : { requestId: event.requestId },
      );
    };
    handleRequest().catch(() => {});
  });
  await protocol.send('Fetch.enable', {
    patterns: [{ urlPattern: '*', requestStage: 'Request' }],
  });
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

  mainResponse = await boundary.guard(page.goto(previewUrl.href, {
    waitUntil: 'networkidle',
    timeout: options.timeoutMs,
  }));
  for (const selector of options.click) {
    await boundary.guard(page.locator(selector).click({ timeout: options.timeoutMs }));
    await boundary.guard(settlePage(page, options.timeoutMs, CLICK_STABLE_WINDOW_MS, navigationState));
  }
  await boundary.guard(page.evaluate(() => window.scrollTo(0, 0)));
  const settling = await boundary.guard(settlePage(
    page,
    options.timeoutMs,
    options.click.length ? CLICK_STABLE_WINDOW_MS : DEFAULT_STABLE_WINDOW_MS,
    navigationState,
  ));
  await boundary.guard(waitForFontsAndFrames(page));

  const geometry = await boundary.guard(page.evaluate(collectGeometry));

  const screenshot = await boundary.guard(page.screenshot({
    fullPage: options.fullPage,
    animations: 'disabled',
    caret: 'hide',
  }));

  const report = {
    schema: 'durable-workflow.pipeline.visual-capture/v1',
    captured_at: new Date().toISOString(),
    surface: String(options.surface).trim(),
    state: String(options.state || 'default').trim() || 'default',
    viewport: { width: options.width, height: options.height },
    full_page: options.fullPage,
    interactions: options.click.map((selector) => ({ type: 'click', selector })),
    page_status: mainResponse?.status() || 0,
    title: await boundary.guard(page.title()),
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
  await context.close();
  context = undefined;
  boundary.throwIfRejected();
  fs.writeFileSync(screenshotPath, screenshot);
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  updateManifest(options, screenshotPath, reportPath, report);
  process.stdout.write(`${JSON.stringify(report)}\n`);
  const failures = reportFailures(report);
  if (failures.length) {
    process.stderr.write(`visual capture failed: ${failures.join(', ')}\n`);
    process.exitCode = 1;
  }
} catch (error) {
  const boundaryFailure = boundary.violation()
    ? new Error(`request boundary rejected a ${boundary.violation().destination} for ${boundary.violation().kind}`)
    : error;
  process.stderr.write(`visual capture error: ${sanitizeFailure(boundaryFailure)}\n`);
  process.exitCode = 1;
} finally {
  if (context) await context.close().catch(() => {});
  await browser.close();
  await closeServer(boundaryProxy);
}
