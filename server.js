const fastify = require('fastify')({ logger: true });
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

const SETTINGS_PATH = path.join(__dirname, 'data', 'settings.json');
const XRAY_CONFIG_PATH = path.join(__dirname, 'xray', 'config.json');

const ALLOWED_DURATIONS = [1, 3, 6, 12];
const ALLOWED_TRAFFIC = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

function env(key, fallback) {
  return process.env[key] !== undefined ? process.env[key] : fallback;
}

function addMonths(date, months) {
  const result = new Date(date);
  result.setMonth(result.getMonth() + months);
  return result;
}

function isValidUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function normalizePath(value) {
  const raw = String(value || '/').trim();
  return raw.startsWith('/') ? raw : `/${raw}`;
}

function defaultSettings() {
  const address = env('ADDRESS', 'isatis-panel-xray-production.up.railway.app');
  const durationMonths = Number(env('DURATION_MONTHS', '1'));

  return {
    name: env('CONFIG_NAME', 'Railway-VLESS'),
    address,
    port: Number(env('CLIENT_PORT', '443')),
    uuid: env('UUID', crypto.randomUUID()),
    path: env('WS_PATH', '/api/v1/shadcdn/'),
    host: env('HOST', address),
    sni: env('SNI', address),
    fingerprint: env('FINGERPRINT', 'chrome'),
    alpn: env('ALPN', 'h2,http/1.1'),
    tls: true,
    durationMonths,
    trafficLimitGB: Number(env('TRAFFIC_LIMIT_GB', '10')),
    expiresAt: addMonths(new Date(), durationMonths).toISOString(),
    bytesUsed: 0,
    disabled: false,
    disabledReason: null
  };
}

function validateSettings(body) {
  const settings = {
    name: String(body.name || 'Railway-VLESS').trim() || 'Railway-VLESS',
    address: String(body.address || '').trim(),
    port: Number(body.port || 443),
    uuid: String(body.uuid || '').trim(),
    path: normalizePath(body.path),
    host: String(body.host || '').trim(),
    sni: String(body.sni || '').trim(),
    fingerprint: String(body.fingerprint || 'chrome').trim(),
    alpn: String(body.alpn || 'h2,http/1.1').trim(),
    tls: body.tls !== false,
    durationMonths: Number(body.durationMonths || 1),
    trafficLimitGB: Number(body.trafficLimitGB || 10)
  };

  if (!settings.address) {
    throw new Error('آدرس سرور الزامی است');
  }

  if (!Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535) {
    throw new Error('پورت نامعتبر است');
  }

  if (!isValidUuid(settings.uuid)) {
    throw new Error('UUID نامعتبر است');
  }

  if (!ALLOWED_DURATIONS.includes(settings.durationMonths)) {
    throw new Error('محدودیت زمانی نامعتبر است');
  }

  if (!ALLOWED_TRAFFIC.includes(settings.trafficLimitGB)) {
    throw new Error('محدودیت حجم نامعتبر است');
  }

  if (!settings.host) {
    settings.host = settings.address;
  }

  if (!settings.sni) {
    settings.sni = settings.address;
  }

  settings.expiresAt = addMonths(new Date(), settings.durationMonths).toISOString();
  settings.bytesUsed = 0;
  settings.disabled = false;
  settings.disabledReason = null;

  return settings;
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

  const encodedName = encodeURIComponent(settings.name || 'Railway-VLESS');

  return `vless://${settings.uuid}@${settings.address}:${settings.port}?${params.toString()}#${encodedName}`;
}

function buildXrayConfigJson(settings) {
  return {
    log: {
      loglevel: 'warning'
    },
    stats: {},
    api: {
      tag: 'api',
      services: ['StatsService']
    },
    policy: {
      levels: {
        0: {
          statsUserUplink: true,
          statsUserDownlink: true
        }
      }
    },
    inbounds: [
      {
        tag: 'api',
        listen: '127.0.0.1',
        port: 10085,
        protocol: 'dokodemo-door',
        settings: { address: '127.0.0.1' }
      },
      {
        listen: '0.0.0.0',
        port: settings.port,
        protocol: 'vless',
        settings: {
          clients: settings.disabled
            ? []
            : [
                {
                  id: settings.uuid,
                  email: settings.name,
                  level: 0
                }
              ],
          decryption: 'none'
        },
        streamSettings: {
          network: 'ws',
          security: settings.tls ? 'tls' : 'none',
          wsSettings: {
            path: settings.path,
            headers: { Host: settings.host }
          }
        }
      }
    ],
    outbounds: [{ protocol: 'freedom' }],
    routing: {
      rules: [{ type: 'field', inboundTag: ['api'], outboundTag: 'api' }]
    }
  };
}

async function loadSettings() {
  try {
    const raw = await fs.readFile(SETTINGS_PATH, 'utf-8');
    return JSON.parse(raw);
  } catch {
    const settings = defaultSettings();
    await saveSettings(settings);
    return settings;
  }
}

async function saveSettings(settings) {
  await fs.mkdir(path.dirname(SETTINGS_PATH), { recursive: true });
  await fs.writeFile(SETTINGS_PATH, JSON.stringify(settings, null, 2), 'utf-8');
}

async function regenerateXrayConfig(settings) {
  const xrayConfig = buildXrayConfigJson(settings);
  await fs.mkdir(path.dirname(XRAY_CONFIG_PATH), { recursive: true });
  await fs.writeFile(XRAY_CONFIG_PATH, JSON.stringify(xrayConfig, null, 2), 'utf-8');
}

async function restartXray() {
  try {
    await execAsync('pkill -f "xray run" || true');
    exec(`xray run -config ${XRAY_CONFIG_PATH}`, (error) => {
      if (error) {
        fastify.log.error(`خطا در اجرای Xray: ${error.message}`);
      }
    });
  } catch (error) {
    fastify.log.error(`خطا در ری‌استارت Xray: ${error.message}`);
  }
}

// -------------------- مانیتورینگ زمان و حجم --------------------

async function getUserTrafficBytes(email) {
  try {
    const uplinkCmd = `xray api stats --server=127.0.0.1:10085 -name "user>>>${email}>>>traffic>>>uplink"`;
    const downlinkCmd = `xray api stats --server=127.0.0.1:10085 -name "user>>>${email}>>>traffic>>>downlink"`;

    const [uplinkResult, downlinkResult] = await Promise.all([
      execAsync(uplinkCmd),
      execAsync(downlinkCmd)
    ]);

    const uplink = parseInt(uplinkResult.stdout.match(/value:(\d+)/)?.[1] || '0', 10);
    const downlink = parseInt(downlinkResult.stdout.match(/value:(\d+)/)?.[1] || '0', 10);

    return uplink + downlink;
  } catch {
    return 0;
  }
}

async function disableUserDueToLimit(settings, reason) {
  settings.disabled = true;
  settings.disabledReason = reason;

  await saveSettings(settings);
  await regenerateXrayConfig(settings);
  await restartXray();

  fastify.log.warn(`کاربر ${settings.name} غیرفعال شد. دلیل: ${reason}`);
}

async function checkLimits() {
  const settings = await loadSettings();

  if (settings.disabled) return;

  const now = new Date();
  const expiresAt = new Date(settings.expiresAt);

  if (now >= expiresAt) {
    await disableUserDueToLimit(settings, 'expired');
    return;
  }

  const usedBytes = await getUserTrafficBytes(settings.name);
  const limitBytes = settings.trafficLimitGB * 1024 * 1024 * 1024;

  settings.bytesUsed = usedBytes;
  await saveSettings(settings);

  if (usedBytes >= limitBytes) {
    await disableUserDueToLimit(settings, 'traffic_exceeded');
  }
}

function startMonitor() {
  const CHECK_INTERVAL_MS = 60 * 1000; // هر ۱ دقیقه

  setInterval(() => {
    checkLimits().catch((error) => {
      fastify.log.error(`خطا در بررسی محدودیت‌ها: ${error.message}`);
    });
  }, CHECK_INTERVAL_MS);
}

// -------------------- روت‌ها --------------------

app.register(require('@fastify/static'), {
  root: path.join(__dirname, 'public')
});

fastify.get('/dash/page', async (req, res) => {
  return res.sendFile('dashboard.html');
});

fastify.get('/', async (req, res) => {
  return res.type('text/html').send(`
    <html>
      <body style="background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;">
        <h1>سایت در حال تعمیر است</h1>
      </body>
    </html>
  `);
});

fastify.get('/api/config', async (req, res) => {
  const settings = await loadSettings();
  const config = buildVlessUri(settings);

  return res.send({ settings, config });
});

fastify.post('/api/config', async (req, res) => {
  try {
    const settings = validateSettings(req.body);

    await saveSettings(settings);
    await regenerateXrayConfig(settings);
    await restartXray();

    const config = buildVlessUri(settings);

    return res.send({ success: true, config, settings });
  } catch (error) {
    return res.status(400).send({ error: error.message });
  }
});

fastify.get('/api/status', async (req, res) => {
  const settings = await loadSettings();

  return res.send({
    disabled: settings.disabled,
    disabledReason: settings.disabledReason,
    expiresAt: settings.expiresAt,
    bytesUsed: settings.bytesUsed,
    trafficLimitGB: settings.trafficLimitGB
  });
});

// -------------------- شروع سرور --------------------

const PORT = Number(env('PORT', '3000'));

fastify.listen({ port: PORT, host: '0.0.0.0' }, async (error) => {
  if (error) {
    fastify.log.error(error);
    process.exit(1);
  }

  const settings = await loadSettings();
  await regenerateXrayConfig(settings);
  await restartXray();

  startMonitor();

  fastify.log.info(`سرور روی پورت ${PORT} اجرا شد`);
});