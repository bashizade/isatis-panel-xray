'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawn, execSync } = require('child_process');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');

const fastify = require('fastify')({ logger: true });

// ------------------------------------------------------------------
// ثابت‌ها و تنظیمات پایه
// ------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const DASHBOARD_PATH = '/dash/page';
const MAIN_DOMAIN = process.env.XRAY_HOST || 'isatis-panel-xray-production.up.railway.app';
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'panel.db');
const XRAY_BIN = process.env.XRAY_BIN || path.join(__dirname, 'bin', 'xray');
const XRAY_CONFIG_PATH = path.join(__dirname, 'xray-config.json');
const XRAY_WS_PORT = 10086; // فقط داخلی - هرگز به بیرون expose نمی‌شود
const XRAY_STATS_PORT = 10085;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// متغیرهای اتصال که فقط یک‌بار از Railway Environment Variables خوانده می‌شوند
const BASE = {
  address: process.env.XRAY_ADDRESS || MAIN_DOMAIN,
  port: Number(process.env.XRAY_PORT) || 443,
  host: process.env.XRAY_HOST || MAIN_DOMAIN,
  path: process.env.XRAY_PATH || '/vless-ws',
  tls: process.env.XRAY_TLS !== 'false',
  sni: process.env.XRAY_SNI || MAIN_DOMAIN,
  fingerprint: process.env.XRAY_FINGERPRINT || 'chrome',
  alpn: (process.env.XRAY_ALPN || 'h2,http/1.1').split(',')
};

const VOLUME_OPTIONS_GB = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
const DURATION_OPTIONS_DAYS = { '1m': 30, '3m': 90, '6m': 180, '1y': 365 };

let xrayProcess = null;

// ------------------------------------------------------------------
// راه‌اندازی دیتابیس (SQLite)
// ------------------------------------------------------------------
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    uuid TEXT UNIQUE NOT NULL,
    duration_key TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    volume_limit_bytes INTEGER NOT NULL,
    volume_used_bytes INTEGER DEFAULT 0,
    connection_limit INTEGER DEFAULT 1,
    disabled INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

function seedDefaultAdmin() {
  const existing = db.prepare('SELECT id FROM admins LIMIT 1').get();
  if (!existing) {
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin123';
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(username, hash);
    fastify.log.warn(`ادمین پیش‌فرض ساخته شد: ${username} / ${password} — لطفاً بعد از ورود رمز را عوض کنید`);
  }
}
seedDefaultAdmin();

// ------------------------------------------------------------------
// پلاگین‌ها
// ------------------------------------------------------------------
fastify.register(require('@fastify/cookie'));
fastify.register(require('@fastify/jwt'), {
  secret: JWT_SECRET,
  cookie: { cookieName: 'token', signed: false }
});
fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, 'public'),
  prefix: '/public/'
});

fastify.decorate('authenticate', async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch {
    reply.code(401).send({ error: 'Unauthorized' });
  }
});

// ------------------------------------------------------------------
// تولید کانفیگ Xray
// ------------------------------------------------------------------
function getActiveClients() {
  const now = new Date().toISOString();
  return db.prepare(`
    SELECT uuid, name FROM users
    WHERE disabled = 0
      AND expires_at > ?
      AND volume_used_bytes < volume_limit_bytes
  `).all(now);
}

function buildXrayConfigJson() {
  const clients = getActiveClients().map((u) => ({
    id: u.uuid,
    email: u.name,
    level: 0
  }));

  return {
    log: { loglevel: 'warning' },
    stats: {},
    api: { tag: 'api', services: ['StatsService'] },
    policy: {
      levels: { 0: { statsUserUplink: true, statsUserDownlink: true } },
      system: { statsInboundUplink: true, statsInboundDownlink: true }
    },
    inbounds: [
      {
        tag: 'api',
        listen: '127.0.0.1',
        port: XRAY_STATS_PORT,
        protocol: 'dokodemo-door',
        settings: { address: '127.0.0.1' }
      },
      {
        tag: 'vless-in',
        listen: '127.0.0.1',
        port: XRAY_WS_PORT,
        protocol: 'vless',
        settings: { clients, decryption: 'none' },
        streamSettings: {
          network: 'ws',
          security: 'none', // TLS توسط Railway Edge ترمینیت می‌شود
          wsSettings: {
            path: BASE.path,
            headers: { Host: BASE.host }
          }
        }
      }
    ],
    outbounds: [{ protocol: 'freedom', tag: 'direct' }],
    routing: {
      rules: [{ type: 'field', inboundTag: ['api'], outboundTag: 'api' }]
    }
  };
}

async function regenerateXrayConfig() {
  fs.writeFileSync(XRAY_CONFIG_PATH, JSON.stringify(buildXrayConfigJson(), null, 2));
}

function stopXray() {
  return new Promise((resolve) => {
    if (!xrayProcess) return resolve();
    xrayProcess.once('exit', () => resolve());
    xrayProcess.kill('SIGTERM');
    xrayProcess = null;
  });
}

async function startXray() {
  await stopXray();

  if (!fs.existsSync(XRAY_BIN)) {
    fastify.log.error(`باینری Xray در مسیر ${XRAY_BIN} یافت نشد. سرویس VPN غیرفعال است، ولی پنل ادامه می‌دهد.`);
    xrayProcess = null;
    return;
  }

  xrayProcess = spawn(XRAY_BIN, ['run', '-config', XRAY_CONFIG_PATH], {
    stdio: ['ignore', 'pipe', 'pipe']
  });

  // این خط کلیدیه - جلوی کرش کل پروسه رو می‌گیره
  xrayProcess.on('error', (err) => {
    fastify.log.error(`اجرای Xray با خطا مواجه شد: ${err.message}`);
    xrayProcess = null;
  });

  xrayProcess.stdout.on('data', (chunk) => fastify.log.info(`[xray] ${chunk.toString().trim()}`));
  xrayProcess.stderr.on('data', (chunk) => fastify.log.error(`[xray] ${chunk.toString().trim()}`));

  xrayProcess.on('exit', (code, signal) => {
    fastify.log.warn(`Xray با کد ${code} (سیگنال: ${signal}) متوقف شد`);
    xrayProcess = null;
  });
}

async function restartXray() {
  await regenerateXrayConfig();
  await startXray();
}

function getXrayVersion() {
  try {
    return execSync(`${XRAY_BIN} version`).toString().split('\n')[0];
  } catch {
    return 'نامشخص';
  }
}

// ------------------------------------------------------------------
// مانیتور انقضا و اتمام حجم
// (اتصال به Stats API واقعی Xray - نیازمند پیاده‌سازی gRPC/HTTP جداگانه)
// ------------------------------------------------------------------
function checkExpiredUsers() {
  const now = new Date().toISOString();
  const expired = db.prepare(`
    SELECT id, name FROM users
    WHERE disabled = 0 AND (expires_at <= ? OR volume_used_bytes >= volume_limit_bytes)
  `).all(now);

  if (expired.length > 0) {
    db.prepare(`
      UPDATE users SET disabled = 1
      WHERE disabled = 0 AND (expires_at <= ? OR volume_used_bytes >= volume_limit_bytes)
    `).run(now);

    expired.forEach((u) => fastify.log.info(`کاربر «${u.name}» به دلیل انقضا/اتمام حجم غیرفعال شد`));
    restartXray();
  }
}

function startUsageMonitor() {
  setInterval(checkExpiredUsers, 60 * 1000);
}

// ------------------------------------------------------------------
// توابع کمکی
// ------------------------------------------------------------------
function buildVlessUri(user) {
  const params = new URLSearchParams({
    type: 'ws',
    security: BASE.tls ? 'tls' : 'none',
    path: BASE.path,
    host: BASE.host,
    sni: BASE.sni,
    fp: BASE.fingerprint,
    alpn: BASE.alpn.join(',')
  });

  return `vless://${user.uuid}@${BASE.address}:${BASE.port}?${params.toString()}#${encodeURIComponent(user.name)}`;
}

const gbToBytes = (gb) => gb * 1024 * 1024 * 1024;

// ------------------------------------------------------------------
// نگهبان صفحه نگهداری - فقط دامنه اصلی و مسیر ریشه
// ------------------------------------------------------------------
fastify.addHook('onRequest', async (request, reply) => {
  const host = request.headers.host || '';
  const isRootPath = request.url === '/' || request.url === '';

  if (host.includes(MAIN_DOMAIN) && isRootPath) {
    reply.type('text/html').send(`
      <!DOCTYPE html>
      <html lang="fa" dir="rtl">
      <head>
        <meta charset="UTF-8" />
        <title>سایت در حال تعمیر است</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gray-950 text-white flex items-center justify-center min-h-screen">
        <div class="text-center space-y-4">
          <h1 class="text-3xl font-bold">🚧 سایت در حال تعمیر است</h1>
          <p class="text-gray-400">لطفاً بعداً دوباره تلاش کنید</p>
        </div>
      </body>
      </html>
    `);
  }
});

// ------------------------------------------------------------------
// احراز هویت
// ------------------------------------------------------------------
fastify.post('/api/v1/auth/login', async (request, reply) => {
  const { username, password } = request.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);

  if (!admin || !bcrypt.compareSync(password || '', admin.password_hash)) {
    return reply.code(401).send({ error: 'نام کاربری یا رمز عبور اشتباه است' });
  }

  const token = fastify.jwt.sign(
    { id: admin.id, username: admin.username, role: admin.role },
    { expiresIn: '12h' }
  );

  reply.setCookie('token', token, { path: '/', httpOnly: true, sameSite: 'strict' });
  return { success: true, token };
});

fastify.post('/api/v1/auth/logout', async (request, reply) => {
  reply.clearCookie('token', { path: '/' });
  return { success: true };
});

// ------------------------------------------------------------------
// صفحه داشبورد
// ------------------------------------------------------------------
fastify.get(DASHBOARD_PATH, async (request, reply) => {
  return reply.sendFile('dashboard.html');
});

// ------------------------------------------------------------------
// API آمار داشبورد
// ------------------------------------------------------------------
fastify.get('/api/v1/stats', { preHandler: [fastify.authenticate] }, async () => {
  const now = new Date().toISOString();
  return {
    totalUsers: db.prepare('SELECT COUNT(*) c FROM users').get().c,
    activeUsers: db.prepare('SELECT COUNT(*) c FROM users WHERE disabled = 0 AND expires_at > ?').get(now).c,
    expiredUsers: db.prepare('SELECT COUNT(*) c FROM users WHERE disabled = 1 OR expires_at <= ?').get(now).c,
    totalInbounds: 1,
    xrayRunning: xrayProcess !== null,
    xrayVersion: getXrayVersion()
  };
});

// ------------------------------------------------------------------
// مدیریت کاربران/کانفیگ‌ها
// ------------------------------------------------------------------
fastify.get('/api/v1/users', { preHandler: [fastify.authenticate] }, async () => {
  return db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
});

fastify.post('/api/v1/users', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { name, durationKey, volumeGb, connectionLimit } = request.body || {};

  if (!name || !DURATION_OPTIONS_DAYS[durationKey] || !VOLUME_OPTIONS_GB.includes(Number(volumeGb))) {
    return reply.code(400).send({ error: 'پارامترهای ورودی نامعتبر است' });
  }

  const uuid = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + DURATION_OPTIONS_DAYS[durationKey] * 86400 * 1000).toISOString();
  const volumeLimitBytes = gbToBytes(Number(volumeGb));

  db.prepare(`
    INSERT INTO users (name, uuid, duration_key, expires_at, volume_limit_bytes, connection_limit)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(name, uuid, durationKey, expiresAt, volumeLimitBytes, Number(connectionLimit) || 1);

  await restartXray();

  const user = db.prepare('SELECT * FROM users WHERE uuid = ?').get(uuid);
  return { success: true, user, config: buildVlessUri(user) };
});

fastify.delete('/api/v1/users/:id', { preHandler: [fastify.authenticate] }, async (request) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(request.params.id);
  await restartXray();
  return { success: true };
});

fastify.patch('/api/v1/users/:id/toggle', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.params.id);
  if (!user) {
    return reply.code(404).send({ error: 'کاربر یافت نشد' });
  }

  const newStatus = user.disabled ? 0 : 1;
  db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(newStatus, request.params.id);

  await restartXray();

  return { success: true, disabled: !!newStatus };
});

fastify.get('/api/v1/users/:id/config', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(request.params.id);
  if (!user) {
    return reply.code(404).send({ error: 'کاربر یافت نشد' });
  }
  return { config: buildVlessUri(user) };
});

fastify.get('/api/v1/options', { preHandler: [fastify.authenticate] }, async () => {
  return {
    durations: [
      { key: '1m', label: '۱ ماهه', days: 30 },
      { key: '3m', label: '۳ ماهه', days: 90 },
      { key: '6m', label: '۶ ماهه', days: 180 },
      { key: '1y', label: '۱ ساله', days: 365 }
    ],
    volumes: VOLUME_OPTIONS_GB,
    connectionLimits: [1, 2, 3]
  };
});

// ------------------------------------------------------------------
// Health Check - برای Zero-downtime restart روی Railway
// ------------------------------------------------------------------
fastify.get('/healthz', async () => {
  return {
    status: 'ok',
    xrayRunning: xrayProcess !== null,
    xrayBinaryExists: fs.existsSync(XRAY_BIN)
  };
});

// ------------------------------------------------------------------
// ثبت Reverse Proxy به سمت Xray (باید بعد از سایر روت‌ها ثبت شود)
// ------------------------------------------------------------------
async function registerXrayProxy() {
  await fastify.register(require('@fastify/http-proxy'), {
    upstream: `http://127.0.0.1:${XRAY_WS_PORT}`,
    prefix: BASE.path,
    rewritePrefix: BASE.path,
    websocket: true,
    replyOptions: {
      onError: (reply, error) => {
        fastify.log.error(`خطای پروکسی به Xray: ${error.message}`);
        reply.code(502).send({ error: 'Bad Gateway' });
      }
    }
  });
}

// ------------------------------------------------------------------
// راه‌اندازی نهایی سرور
// ------------------------------------------------------------------
async function start() {
  try {
    await regenerateXrayConfig();
    await startXray();
    await registerXrayProxy();
    startUsageMonitor();

    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    fastify.log.info(`سرور روی پورت ${PORT} اجرا شد`);
    fastify.log.info(`داشبورد: ${DASHBOARD_PATH}`);
  } catch (error) {
    fastify.log.error(error);
    process.exit(1);
  }
}

// ------------------------------------------------------------------
// مدیریت خاموش شدن تمیز (Graceful Shutdown)
// ------------------------------------------------------------------
process.on('SIGTERM', async () => {
  fastify.log.info('دریافت SIGTERM - در حال خاموش شدن تمیز...');
  await stopXray();
  await fastify.close();
  db.close();
  process.exit(0);
});

start();