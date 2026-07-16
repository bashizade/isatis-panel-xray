require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const httpProxy = require('http-proxy');

const app = express();
const server = http.createServer(app);
const proxy = httpProxy.createProxyServer({});

// ========== تنظیمات محیطی ==========
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const XRAY_BASE_PORT = parseInt(process.env.XRAY_BASE_PORT || '10086');
const DB_PATH = process.env.DB_PATH || './data/configs.db';
const COOKIE_NAME = 'panel_auth';
const COOKIE_VALUE = 'authenticated';

// ساخت پوشه دیتا
if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });

const db = new sqlite3.Database(DB_PATH);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// ساخت جدول کانفیگ‌ها
db.run(`
  CREATE TABLE IF NOT EXISTS configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    address TEXT,
    port TEXT,
    uuid TEXT,
    protocol TEXT,
    host TEXT,
    path TEXT,
    tls TEXT,
    fp TEXT,
    alpn TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// میان‌افزار احراز هویت
function requireAuth(req, res, next) {
  if (req.cookies[COOKIE_NAME] === COOKIE_VALUE) return next();
  res.redirect('/dash');
}

// ========== روت‌های عمومی ==========
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/dash', (req, res) => {
  res.sendFile(__dirname + '/public/dash.html');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie(COOKIE_NAME, COOKIE_VALUE, { httpOnly: true });
    return res.redirect('/dash/view');
  }
  res.send('نام کاربری یا رمز عبور اشتباه است. <a href="/dash">بازگشت</a>');
});

app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/dash');
});

// ========== روت‌های محافظت‌شده داشبورد ==========
app.get('/dash/view', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/dash-view.html');
});

app.get('/api/configs', requireAuth, (req, res) => {
  db.all("SELECT * FROM configs ORDER BY id DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/save', requireAuth, (req, res) => {
  let { username, address, port, uuid, protocol, host, path, tls, fp, alpn } = req.body;
  if (!path.startsWith('/')) path = '/' + path;

  db.run(
    `INSERT INTO configs (username, address, port, uuid, protocol, host, path, tls, fp, alpn) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [username, address, port, uuid, protocol, host, path, tls, fp, alpn],
    function(err) {
      if (err) return res.status(500).send('خطای دیتابیس: ' + err.message);

      // ساخت لینک کانفیگ با فرمت استاندارد
      const params = new URLSearchParams();
      params.set('encryption', 'none');
      params.set('security', tls);
      params.set('sni', host);
      params.set('fp', fp);
      params.set('alpn', alpn);
      params.set('insecure', '0');
      params.set('allowInsecure', '0');
      params.set('type', protocol);
      params.set('host', host);
      params.set('path', path);
      if (protocol === 'xhttp') params.set('mode', 'auto');

      const link = `vless://${uuid}@${address}:${port}?${params.toString()}#${encodeURIComponent(username)}`;

      regenerateXrayConfig().then(() => {
        restartXray();
        res.json({ success: true, link, id: this.lastID });
      }).catch(e => {
        res.json({ success: true, link, id: this.lastID, warning: e.message });
      });
    }
  );
});

// ========== مدیریت Xray ==========
function createInbound(row) {
  const internalPort = XRAY_BASE_PORT + row.id;
  const inbound = {
    listen: "127.0.0.1",
    port: internalPort,
    protocol: "vless",
    settings: {
      clients: [{ id: row.uuid, email: row.username, flow: "" }],
      decryption: "none"
    },
    streamSettings: {
      network: row.protocol,
      security: "none"
    },
    sniffing: {
      enabled: true,
      destOverride: ["http", "tls"]
    }
  };

  if (row.protocol === 'ws') {
    inbound.streamSettings.wsSettings = {
      path: row.path,
      headers: { Host: row.host }
    };
  } else if (row.protocol === 'xhttp') {
    inbound.streamSettings.xhttpSettings = {
      path: row.path,
      host: row.host,
      mode: "auto"
    };
  } else if (row.protocol === 'grpc') {
    inbound.streamSettings.grpcSettings = {
      serviceName: row.path.replace(/^\//, '')
    };
  }

  return inbound;
}

function regenerateXrayConfig() {
  return new Promise((resolve, reject) => {
    db.all("SELECT * FROM configs", [], (err, rows) => {
      if (err) return reject(err);

      const inbounds = rows.map(createInbound);

      // اگر هیچ کانفیگی نیست، یک inbound پوشه بسازیم که Xray خطا نده
      if (inbounds.length === 0) {
        inbounds.push({
          listen: "127.0.0.1",
          port: XRAY_BASE_PORT,
          protocol: "vless",
          settings: {
            clients: [{ id: "00000000-0000-0000-0000-000000000000" }],
            decryption: "none"
          },
          streamSettings: {
            network: "ws",
            security: "none",
            wsSettings: { path: "/none" }
          }
        });
      }

      const config = {
        log: { loglevel: "warning" },
        inbounds,
        outbounds: [
          { protocol: "freedom", tag: "direct" },
          { protocol: "blackhole", tag: "block" }
        ]
      };

      fs.writeFileSync('/tmp/xray-config.json', JSON.stringify(config, null, 2));
      updatePathMap(rows);
      resolve();
    });
  });
}

// نقشه مسیر به پورت داخلی Xray
let pathToPortMap = {};

function updatePathMap(rows) {
  pathToPortMap = {};
  rows.forEach(row => {
    pathToPortMap[row.path] = XRAY_BASE_PORT + row.id;
  });
}

function getTargetPort(reqPath) {
  for (const [path, port] of Object.entries(pathToPortMap)) {
    if (reqPath === path || reqPath.startsWith(path + '/')) return port;
  }
  return null;
}

let xrayProcess = null;

function restartXray() {
  if (xrayProcess) {
    xrayProcess.kill();
    xrayProcess = null;
  }

  if (!fs.existsSync('/tmp/xray-config.json')) return;

  xrayProcess = spawn('xray', ['-c', '/tmp/xray-config.json']);
  xrayProcess.stdout.on('data', d => console.log('XRAY:', d.toString().trim()));
  xrayProcess.stderr.on('data', d => console.error('XRAY ERR:', d.toString().trim()));
  xrayProcess.on('exit', code => console.log('Xray exited with code', code));
}

// ========== پراکسی ترافیک VPN به Xray ==========
app.use((req, res) => {
  const targetPort = getTargetPort(req.path);
  if (!targetPort) {
    return res.status(404).send('Not found');
  }

  proxy.web(req, res, { target: `http://127.0.0.1:${targetPort}` }, (err) => {
    if (err) {
      console.error('Proxy error:', err);
      res.status(502).send('Xray proxy error');
    }
  });
});

server.on('upgrade', (req, socket, head) => {
  const targetPort = getTargetPort(req.url);
  if (!targetPort) {
    socket.destroy();
    return;
  }

  proxy.ws(req, socket, head, { target: `http://127.0.0.1:${targetPort}` }, (err) => {
    console.error('WS Proxy error:', err);
    socket.destroy();
  });
});

// ========== استارت سرور ==========
(async () => {
  await regenerateXrayConfig();
  restartXray();
  server.listen(PORT, () => {
    console.log(`Panel running on port ${PORT}`);
    console.log(`Admin user: ${ADMIN_USER}`);
  });
})();