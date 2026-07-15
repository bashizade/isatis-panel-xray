'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const httpProxy = require('http-proxy');
const Fastify = require('fastify');
const fastifyStatic = require('@fastify/static');

const app = Fastify({
  logger: true
});

const PORT = Number(process.env.PORT || 3000);
const XRAY_PORT = 10086;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const XRAY_CONFIG_FILE = path.join(DATA_DIR, 'xray.json');

const DASH_PASSWORD = process.env.DASH_PASSWORD || '';

fs.mkdirSync(DATA_DIR, { recursive: true });

let xrayProcess = null;
let currentSettings = null;

function env(name, fallback = '') {
  return String(process.env[name] || fallback).trim();
}

function defaultSettings() {
  const address = env('ADDRESS', 'isatis-panel-xray-production.up.railway.app');

  return {
    address,
    port: Number(env('CLIENT_PORT', '443')),
    uuid: env('UUID', crypto.randomUUID()),
    path: env('WS_PATH', '/api/v1/shadcdn/'),
    host: env('HOST', address),
    sni: env('SNI', address),
    fingerprint: env('FINGERPRINT', 'chrome'),
    alpn: env('ALPN', 'h2,http/1.1'),
    tls: true
  };
}

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const saved = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
      return {
        ...defaultSettings(),
        ...saved
      };
    }
  } catch (error) {
    app.log.error(error, 'Could not load settings');
  }

  return defaultSettings();
}

function saveSettings(settings) {
  fs.writeFileSync(
    SETTINGS_FILE,
    JSON.stringify(settings, null, 2),
    'utf8'
  );
}

function normalizePath(value) {
  let result = String(value || '/').trim();

  if (!result.startsWith('/')) {
    result = `/${result}`;
  }

  if (!result.endsWith('/')) {
    result += '/';
  }

  return result;
}

function isValidUuid(uuid) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

function validateSettings(body) {
  const settings = {
    address: String(body.address || '').trim(),
    port: Number(body.port || 443),
    uuid: String(body.uuid || '').trim(),
    path: normalizePath(body.path),
    host: String(body.host || '').trim(),
    sni: String(body.sni || '').trim(),
    fingerprint: String(body.fingerprint || 'chrome').trim(),
    alpn: String(body.alpn || 'h2,http/1.1').trim(),
    tls: body.tls !== false
  };

  if (!settings.address) {
    throw new Error('Address is required');
  }

  if (!Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535) {
    throw new Error('Invalid port');
  }

  if (!isValidUuid(settings.uuid)) {
    throw new Error('Invalid UUID');
  }

  if (!settings.host) {
    settings.host = settings.address;
  }

  if (!settings.sni) {
    settings.sni = settings.address;
  }

  return settings;
}

function createXrayConfig(settings) {
  return {
    log: {
      loglevel: 'warning'
    },
    inbounds: [
      {
        tag: 'vless-ws-in',
        listen: '127.0.0.1',
        port: XRAY_PORT,
        protocol: 'vless',
        settings: {
          clients: [
            {
              id: settings.uuid,
              level: 0
            }
          ],
          decryption: 'none'
        },
        streamSettings: {
          network: 'ws',
          security: 'none',
          wsSettings: {
            path: settings.path,
            headers: {
              Host: settings.host
            }
          }
        }
      }
    ],
    outbounds: [
      {
        tag: 'direct',
        protocol: 'freedom',
        settings: {}
      },
      {
        tag: 'block',
        protocol: 'blackhole',
        settings: {}
      }
    ]
  };
}

function stopXray() {
  if (xrayProcess) {
    app.log.info('Stopping Xray');
    xrayProcess.kill('SIGTERM');
    xrayProcess = null;
  }
}

function startXray(settings) {
  stopXray();

  const config = createXrayConfig(settings);

  fs.writeFileSync(
    XRAY_CONFIG_FILE,
    JSON.stringify(config, null, 2),
    'utf8'
  );

  app.log.info({
    address: settings.address,
    path: settings.path,
    xrayPort: XRAY_PORT
  }, 'Starting Xray');

  xrayProcess = spawn(
    'xray',
    ['run', '-c', XRAY_CONFIG_FILE],
    {
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );

  xrayProcess.stdout.on('data', (data) => {
    app.log.info(`[xray] ${data.toString().trim()}`);
  });

  xrayProcess.stderr.on('data', (data) => {
    app.log.warn(`[xray] ${data.toString().trim()}`);
  });

  xrayProcess.on('exit', (code, signal) => {
    app.log.warn({ code, signal }, 'Xray stopped');
    xrayProcess = null;
  });
}

function buildVlessUri(settings) {
  const params = new URLSearchParams();

  params.set('encryption', 'none');
  params.set('security', settings.tls ? 'tls' : 'none');
  params.set('type', 'ws');
  params.set('host', settings.host);
  params.set('path', settings.path);

  if (settings.tls) {
    params.set('sni', settings.sni);
    params.set('fp', settings.fingerprint);

    if (settings.alpn) {
      params.set('alpn', settings.alpn);
    }
  }

  return `vless://${settings.uuid}@${settings.address}:${settings.port}?${params.toString()}#IsatisStack-VLESS`;
}

function checkPassword(request, reply) {
  if (!DASH_PASSWORD) {
    return true;
  }

  const password = request.headers['x-dashboard-password'];

  if (password !== DASH_PASSWORD) {
    reply.code(401).send({
      success: false,
      error: 'Unauthorized'
    });

    return false;
  }

  return true;
}

currentSettings = loadSettings();

app.register(fastifyStatic, {
  root: path.join(__dirname, 'public'),
  prefix: '/public/'
});

app.get('/', async (request, reply) => {
  return reply.sendFile('maintenance.html');
});

app.get('/dash/page', async (request, reply) => {
  return reply.sendFile('dashboard.html');
});

app.get('/api/config', async (request, reply) => {
  if (!checkPassword(request, reply)) return;

  return {
    success: true,
    settings: currentSettings,
    config: buildVlessUri(currentSettings)
  };
});

app.post('/api/config', async (request, reply) => {
  if (!checkPassword(request, reply)) return;

  try {
    const settings = validateSettings(request.body || {});

    currentSettings = settings;
    saveSettings(settings);
    startXray(settings);

    return {
      success: true,
      message: 'Configuration saved successfully',
      settings,
      config: buildVlessUri(settings)
    };
  } catch (error) {
    return reply.code(400).send({
      success: false,
      error: error.message
    });
  }
});

app.get('/health', async () => {
  return {
    status: 'ok',
    xray: Boolean(xrayProcess)
  };
});

const proxy = httpProxy.createProxyServer({
  target: `http://127.0.0.1:${XRAY_PORT}`,
  ws: true,
  changeOrigin: false
});

proxy.on('error', (error, request, socket) => {
  app.log.error(error, 'WebSocket proxy error');

  if (socket && !socket.destroyed) {
    socket.destroy();
  }
});

async function start() {
  startXray(currentSettings);

  await app.listen({
    port: PORT,
    host: '0.0.0.0'
  });

  app.log.info(`Dashboard available at /dash/page`);
  app.log.info(`Public server listening on port ${PORT}`);

  app.server.on('upgrade', (request, socket, head) => {
    try {
      const requestUrl = new URL(
        request.url,
        `http://${request.headers.host || 'localhost'}`
      );

      const configuredPath = currentSettings.path.replace(/\/+$/, '');
      const requestedPath = requestUrl.pathname.replace(/\/+$/, '');

      if (requestedPath !== configuredPath) {
        socket.destroy();
        return;
      }

      proxy.ws(request, socket, head);
    } catch (error) {
      app.log.error(error, 'Upgrade error');
      socket.destroy();
    }
  });
}

async function shutdown() {
  stopXray();
  await app.close();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

start().catch((error) => {
  app.log.error(error);
  process.exit(1);
});