require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

const PORT = process.env.PORT || 3000;
const LOG_FILE = process.env.SURICATA_LOG || '/mnt/suricata-logs/eve.json';
const AUTH_USER = process.env.AUTH_USER || 'admin';
const AUTH_PASS = process.env.AUTH_PASS || 'suricata';
const WEBHOOK_URL = process.env.WEBHOOK_URL || '';
const DB_FILE = process.env.DB_FILE || './data/alerts.db';

const dataDir = path.dirname(DB_FILE);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(DB_FILE);
db.exec(`
  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    severity TEXT,
    signature TEXT,
    source_ip TEXT,
    source_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp);
  CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity);
  CREATE INDEX IF NOT EXISTS idx_source_ip ON alerts(source_ip);
`);

const insertAlert = db.prepare(`
  INSERT INTO alerts (timestamp, severity, signature, source_ip, source_port, dest_ip, dest_port, protocol)
  VALUES (@timestamp, @severity, @signature, @source_ip, @source_port, @dest_ip, @dest_port, @protocol)
`);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Demasiadas peticiones, intenta más tarde' }
});

app.use('/api/', apiLimiter);
app.use(express.static(path.join(__dirname, 'public')));

const basicAuth = (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/') {
    const auth = req.headers.authorization;
    if (!auth) {
      res.setHeader('WWW-Authenticate', 'Basic realm="Suricata Dashboard"');
      return res.status(401).send('Autenticación requerida');
    }
    const [user, pass] = Buffer.from(auth.split(' ')[1], 'base64').toString().split(':');
    if (user !== AUTH_USER || pass !== AUTH_PASS) {
      return res.status(403).send('Credenciales incorrectas');
    }
  }
  next();
};
app.use(basicAuth);

let metrics = {
  totalAlerts: 0,
  alertsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  alertsByProtocol: { TCP: 0, UDP: 0, ICMP: 0, HTTP: 0, HTTPS: 0, DNS: 0 },
  alertsBySourceIP: {},
  alertsByDestIP: {},
  recentAlerts: [],
  alertsTimeline: [],
  topSignatures: {},
  lastUpdate: null
};

function loadMetricsFromDB() {
  try {
    const totalResult = db.prepare('SELECT COUNT(*) as count FROM alerts').get();
    metrics.totalAlerts = totalResult?.count || 0;

    const severityResult = db.prepare('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity').all();
    severityResult.forEach(row => {
      if (metrics.alertsBySeverity.hasOwnProperty(row.severity)) {
        metrics.alertsBySeverity[row.severity] = row.count;
      }
    });

    const protocolResult = db.prepare('SELECT protocol, COUNT(*) as count FROM alerts GROUP BY protocol').all();
    protocolResult.forEach(row => {
      const proto = row.protocol?.toUpperCase();
      if (proto && metrics.alertsByProtocol.hasOwnProperty(proto)) {
        metrics.alertsByProtocol[proto] = row.count;
      }
    });

    const sourceIPResult = db.prepare('SELECT source_ip, COUNT(*) as count FROM alerts GROUP BY source_ip ORDER BY count DESC LIMIT 100').all();
    sourceIPResult.forEach(row => {
      if (row.source_ip) metrics.alertsBySourceIP[row.source_ip] = row.count;
    });

    const destIPResult = db.prepare('SELECT dest_ip, COUNT(*) as count FROM alerts GROUP BY dest_ip ORDER BY count DESC LIMIT 100').all();
    destIPResult.forEach(row => {
      if (row.dest_ip) metrics.alertsByDestIP[row.dest_ip] = row.count;
    });

    const sigResult = db.prepare('SELECT signature, COUNT(*) as count FROM alerts GROUP BY signature ORDER BY count DESC LIMIT 50').all();
    sigResult.forEach(row => {
      if (row.signature) metrics.topSignatures[row.signature] = row.count;
    });

    const recentResult = db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 100').all();
    metrics.recentAlerts = recentResult;

    console.log(`Métricas cargadas desde DB: ${metrics.totalAlerts} alertas`);
  } catch (error) {
    console.error('Error cargando métricas desde DB:', error.message);
  }
}

function emitMetrics() {
  io.emit("metrics", {
    ...metrics,
    topSignatures: Object.entries(metrics.topSignatures).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([sig, count]) => ({ signature: sig, count })),
    topSourceIPs: Object.entries(metrics.alertsBySourceIP).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, count]) => ({ ip, count })),
    topDestIPs: Object.entries(metrics.alertsByDestIP).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, count]) => ({ ip, count }))
  });
}

async function sendWebhook(alert) {
  if (!WEBHOOK_URL) return;
  
  const isDiscord = WEBHOOK_URL.includes('discord');
  const isSlack = WEBHOOK_URL.includes('slack');
  const isTelegram = WEBHOOK_URL.includes('telegram');
  
  let payload;
  
  if (isDiscord) {
    const color = alert.severity === 'critical' ? 16711680 : alert.severity === 'high' ? 16744192 : 16776960;
    payload = {
      embeds: [{
        title: `🚨 ${alert.severity.toUpperCase()} ALERT`,
        color: color,
        fields: [
          { name: 'Signature', value: alert.signature?.substring(0, 100) || 'N/A', inline: false },
          { name: 'Source', value: `${alert.source_ip}:${alert.source_port}`, inline: true },
          { name: 'Destination', value: `${alert.dest_ip}:${alert.dest_port}`, inline: true },
          { name: 'Protocol', value: alert.protocol || 'N/A', inline: true }
        ],
        timestamp: new Date().toISOString()
      }]
    };
  } else if (isSlack) {
    payload = {
      text: `🚨 *${alert.severity.toUpperCase()} ALERT*\n${alert.signature}\n${alert.source_ip}:${alert.source_port} → ${alert.dest_ip}:${alert.dest_port} [${alert.protocol}]`
    };
  } else if (isTelegram) {
    payload = {
      text: `🚨 *${alert.severity.toUpperCase()} ALERT*\n${alert.signature}\n${alert.source_ip}:${alert.source_port} → ${alert.dest_ip}:${alert.dest_port} [${alert.protocol}]`,
      parse_mode: 'Markdown'
    };
  } else {
    payload = { alert };
  }
  
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (error) {
    console.error('Webhook error:', error.message);
  }
}

app.get('/api/metrics', (req, res) => {
  res.json({
    ...metrics,
    topSignatures: Object.entries(metrics.topSignatures)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([sig, count]) => ({ signature: sig, count })),
    topSourceIPs: Object.entries(metrics.alertsBySourceIP)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count })),
    topDestIPs: Object.entries(metrics.alertsByDestIP)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }))
  });
});

app.get('/api/alerts', (req, res) => {
  let limit = parseInt(req.query.limit) || 50;
  limit = Math.max(1, Math.min(limit, 500));
  
  const severity = req.query.severity;
  const protocol = req.query.protocol;
  const sourceIp = req.query.source_ip;
  const destIp = req.query.dest_ip;
  const from = req.query.from;
  const to = req.query.to;
  
  let query = 'SELECT * FROM alerts WHERE 1=1';
  const params = [];
  
  if (severity) {
    query += ' AND severity = ?';
    params.push(severity);
  }
  if (protocol) {
    query += ' AND protocol = ?';
    params.push(protocol.toUpperCase());
  }
  if (sourceIp) {
    query += ' AND source_ip LIKE ?';
    params.push(`%${sourceIp}%`);
  }
  if (destIp) {
    query += ' AND dest_ip LIKE ?';
    params.push(`%${destIp}%`);
  }
  if (from) {
    query += ' AND timestamp >= ?';
    params.push(from);
  }
  if (to) {
    query += ' AND timestamp <= ?';
    params.push(to);
  }
  
  query += ' ORDER BY id DESC LIMIT ?';
  params.push(limit);
  
  const alerts = db.prepare(query).all(...params);
  res.json(alerts);
});

app.get('/api/alerts/export', (req, res) => {
  const format = req.query.format || 'json';
  const alerts = db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 10000').all();
  
  if (format === 'csv') {
    const header = 'timestamp,severity,signature,source_ip,source_port,dest_ip,dest_port,protocol\n';
    const rows = alerts.map(a => 
      `"${a.timestamp}","${a.severity}","${(a.signature || '').replace(/"/g, '""')}","${a.source_ip}",${a.source_port},"${a.dest_ip}",${a.dest_port},"${a.protocol}"`
    ).join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="alerts.csv"');
    res.send(header + rows);
  } else {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="alerts.json"');
    res.json(alerts);
  }
});

app.get('/api/stats/hourly', (req, res) => {
  const result = db.prepare(`
    SELECT strftime('%H', timestamp) as hour, COUNT(*) as count 
    FROM alerts 
    GROUP BY hour 
    ORDER BY hour
  `).all();
  res.json(result.map(r => ({ hour: r.hour + ':00', count: r.count })));
});

app.get('/api/stats/severity', (req, res) => {
  const result = db.prepare('SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity').all();
  res.json(result);
});

let testInterval = null;

app.get('/api/test/start', (req, res) => {
  if (testInterval) {
    return res.json({ status: 'already running' });
  }
  
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const signatures = [
    'ET MALWARE C2 Traffic', 'SQL Injection Attempt Detected', 'Port Scan Activity',
    'Suspicious User-Agent', 'Brute Force Attack', 'DDoS Attack Pattern',
    'Malware Download Detected', 'Phishing Site Access', 'SSH Brute Force', 'DNS Tunneling Activity'
  ];
  const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP'];
  
  testInterval = setInterval(() => {
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const hour = new Date().getHours();
    
    const publicIPs = [
      '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '208.67.222.222',
      '208.67.220.220', '9.9.9.9', '149.112.112.112', '64.6.64.6',
      '104.16.248.249', '104.16.249.249', '172.217.14.206', '142.250.80.46',
      '23.21.134.22', '52.84.223.108', '13.107.42.14', '204.79.197.200',
      '151.101.1.140', '151.101.65.140', '185.199.108.153', '140.82.112.4'
    ];
    
    const alert = {
      timestamp: new Date().toISOString(),
      severity: severity,
      signature: signatures[Math.floor(Math.random() * signatures.length)] + ' - ' + severity.toUpperCase(),
      source_ip: publicIPs[Math.floor(Math.random() * publicIPs.length)],
      source_port: Math.floor(Math.random() * 65535),
      dest_ip: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      dest_port: [80, 443, 22, 3389, 53, 8080][Math.floor(Math.random() * 6)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)]
    };
    
    addAlert(alert, true);
  }, 2000);
  
  res.json({ status: 'started', message: 'Inyectando alertas cada 2 segundos' });
});

app.get('/api/test/stop', (req, res) => {
  if (testInterval) {
    clearInterval(testInterval);
    testInterval = null;
    res.json({ status: 'stopped' });
  } else {
    res.json({ status: 'not running' });
  }
});

app.get('/api/test/:severity', (req, res) => {
  const severity = req.params.severity;
  const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
  
  if (!validSeverities.includes(severity)) {
    return res.status(400).json({ error: 'Severidad inválida. Usa: critical, high, medium, low, info' });
  }
  
  const publicIPs = [
    '8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9', '104.16.248.249',
    '172.217.14.206', '52.84.223.108', '13.107.42.14', '185.199.108.153'
  ];
  
  const alert = {
    timestamp: new Date().toISOString(),
    severity: severity,
    signature: `TEST ALERT - ${severity.toUpperCase()} - ${Date.now()}`,
    source_ip: publicIPs[Math.floor(Math.random() * publicIPs.length)],
    source_port: Math.floor(Math.random() * 65535),
    dest_ip: `10.0.0.${Math.floor(Math.random() * 255)}`,
    dest_port: [80, 443, 22, 3389][Math.floor(Math.random() * 4)],
    protocol: ['TCP', 'UDP', 'HTTP'][Math.floor(Math.random() * 3)]
  };
  
  addAlert(alert, true);
  res.json({ success: true, alert });
});

app.post('/api/reset', (req, res) => {
  db.exec('DELETE FROM alerts');
  metrics = {
    totalAlerts: 0,
    alertsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    alertsByProtocol: { TCP: 0, UDP: 0, ICMP: 0, HTTP: 0, HTTPS: 0, DNS: 0 },
    alertsBySourceIP: {},
    alertsByDestIP: {},
    recentAlerts: [],
    alertsTimeline: [],
    topSignatures: {},
    lastUpdate: null
  };
  res.json({ success: true });
});

function addAlert(alert, emitWebSocket = true) {
  try {
    insertAlert.run(alert);
  } catch (error) {
    console.error('Error inserting alert:', error.message);
  }
  
  metrics.totalAlerts++;
  metrics.alertsBySeverity[alert.severity] = (metrics.alertsBySeverity[alert.severity] || 0) + 1;
  
  const proto = alert.protocol?.toUpperCase();
  if (proto) {
    metrics.alertsByProtocol[proto] = (metrics.alertsByProtocol[proto] || 0) + 1;
  }
  
  metrics.alertsBySourceIP[alert.source_ip] = (metrics.alertsBySourceIP[alert.source_ip] || 0) + 1;
  metrics.alertsByDestIP[alert.dest_ip] = (metrics.alertsByDestIP[alert.dest_ip] || 0) + 1;
  metrics.topSignatures[alert.signature] = (metrics.topSignatures[alert.signature] || 0) + 1;
  
  metrics.recentAlerts.unshift(alert);
  if (metrics.recentAlerts.length > 100) metrics.recentAlerts.pop();
  
  const hour = new Date().getHours();
  const hourStr = `${hour.toString().padStart(2, '0')}:00`;
  const existingHour = metrics.alertsTimeline.find(h => h.hour === hourStr);
  if (existingHour) {
    existingHour.count++;
  } else {
    metrics.alertsTimeline.push({ hour: hourStr, count: 1 });
  }
  if (metrics.alertsTimeline.length > 24) {
    metrics.alertsTimeline.shift();
  }
  
  metrics.lastUpdate = new Date().toISOString();
  
  if (emitWebSocket) {
    io.emit('newAlert', alert);
    emitMetrics();
    console.log(`Alerta: ${alert.severity.toUpperCase()} - ${alert.signature}`);
    
    if (alert.severity === 'critical' || alert.severity === 'high') {
      sendWebhook(alert);
    }
  }
}

function processAlert(line, emitWebSocket = true) {
  try {
    const event = JSON.parse(line);
    
    if (event.event_type !== 'alert') return;
    
    const alert = event.alert;
    if (!alert) return;
    
    let severity = 'info';
    if (alert.severity <= 1) severity = 'critical';
    else if (alert.severity === 2) severity = 'high';
    else if (alert.severity === 3) severity = 'medium';
    else severity = 'low';
    
    const processedAlert = {
      timestamp: event.timestamp,
      severity: severity,
      signature: alert.signature || 'Unknown',
      source_ip: event.src_ip || 'Unknown',
      source_port: event.src_port || 0,
      dest_ip: event.dest_ip || 'Unknown',
      dest_port: event.dest_port || 0,
      protocol: event.proto || 'Unknown'
    };
    
    addAlert(processedAlert, emitWebSocket);
    
  } catch (error) {
    // Ignorar líneas mal formateadas
  }
}

function loadHistoricalAlerts() {
  console.log('Cargando alertas históricas...');
  
  try {
    const content = fs.readFileSync(LOG_FILE, 'utf8');
    const lines = content.split('\n').filter(line => line.trim());
    
    const recentLines = lines.slice(-1000);
    let alertCount = 0;
    
    recentLines.forEach(line => {
      try {
        const event = JSON.parse(line);
        if (event.event_type === 'alert') {
          processAlert(line, false);
          alertCount++;
        }
      } catch (e) {
        // Ignorar líneas mal formateadas
      }
    });
    
    console.log(`${alertCount} alertas históricas cargadas`);
    emitMetrics();
    
  } catch (error) {
    console.error(`Error cargando alertas históricas: ${error.message}`);
  }
}

let lastFileSize = 0;
let lastFileBuffer = '';

function startPolling() {
  console.log(`Monitoreando archivo: ${LOG_FILE}`);
  
  if (!fs.existsSync(LOG_FILE)) {
    console.error(`ERROR: El archivo ${LOG_FILE} no existe`);
    console.log('Usando modo de prueba. Ejecuta: curl http://localhost:3000/api/test/start');
    return;
  }
  
  loadHistoricalAlerts();
  
  try {
    const stats = fs.statSync(LOG_FILE);
    lastFileSize = stats.size;
    console.log(`Tamaño inicial del archivo: ${lastFileSize} bytes`);
  } catch (e) {
    console.error(`Error obteniendo tamaño del archivo: ${e.message}`);
  }
  
  setInterval(() => {
    try {
      const stats = fs.statSync(LOG_FILE);
      const currentSize = stats.size;
      
      if (currentSize > lastFileSize) {
        const fd = fs.openSync(LOG_FILE, 'r');
        const bytesToRead = currentSize - lastFileSize;
        const buffer = Buffer.alloc(bytesToRead);
        fs.readSync(fd, buffer, 0, bytesToRead, lastFileSize);
        fs.closeSync(fd);
        
        const newData = lastFileBuffer + buffer.toString('utf8');
        const lines = newData.split('\n');
        
        lastFileBuffer = lines.pop() || '';
        
        lines.forEach(line => {
          if (line.trim()) {
            processAlert(line, true);
          }
        });
        
        lastFileSize = currentSize;
      } else if (currentSize < lastFileSize) {
        console.log('Archivo rotado, reiniciando posición...');
        lastFileSize = 0;
        lastFileBuffer = '';
      }
    } catch (error) {
      console.error(`Error en polling: ${error.message}`);
    }
  }, 10000);
  
  console.log('Polling activo cada 10 segundos');
}

io.on('connection', (socket) => {
  console.log('Cliente conectado');
  emitMetrics();

  socket.on('disconnect', () => {
    console.log('Cliente desconectado');
  });
});

function gracefulShutdown(signal) {
  console.log(`\nRecibida señal ${signal}. Cerrando servidor...`);
  
  io.close(() => {
    console.log('WebSocket cerrado');
  });
  
  server.close(() => {
    console.log('Servidor HTTP cerrado');
    db.close();
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('Forzando cierre...');
    db.close();
    process.exit(1);
  }, 5000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

loadMetricsFromDB();

server.listen(PORT, () => {
  console.log(`Dashboard de Suricata ejecutándose en http://localhost:${PORT}`);
  console.log(`Archivo de logs: ${LOG_FILE}`);
  console.log(`Base de datos: ${DB_FILE}`);
  console.log(`Autenticación: ${AUTH_USER}:****`);
  
  startPolling();
});
