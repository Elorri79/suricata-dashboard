const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const LOG_FILE = process.env.SURICATA_LOG || path.join(__dirname, 'logs', 'eve.json');

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Almacenar métricas en memoria
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

// Colores para severity
const severityColors = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#6b7280'
};

// API: Obtener métricas actuales
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

// API: Obtener alertas recientes
app.get('/api/alerts', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json(metrics.recentAlerts.slice(0, limit));
});

// API: Test - inyectar alertas aleatorias cada 2 segundos
let testInterval = null;

app.get('/api/test/start', (req, res) => {
  if (testInterval) {
    return res.json({ status: 'already running' });
  }
  
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const signatures = [
    'ET MALWARE C2 Traffic',
    'SQL Injection Attempt Detected',
    'Port Scan Activity',
    'Suspicious User-Agent',
    'Brute Force Attack',
    'DDoS Attack Pattern',
    'Malware Download Detected',
    'Phishing Site Access',
    'SSH Brute Force',
    'DNS Tunneling Activity'
  ];
  const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP'];
  
  testInterval = setInterval(() => {
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const hour = new Date().getHours();
    
    const alert = {
      timestamp: new Date().toISOString(),
      severity: severity,
      signature: signatures[Math.floor(Math.random() * signatures.length)] + ' - ' + severity.toUpperCase(),
      source_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      source_port: Math.floor(Math.random() * 65535),
      dest_ip: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      dest_port: [80, 443, 22, 3389, 53, 8080][Math.floor(Math.random() * 6)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)]
    };
    
    metrics.totalAlerts++;
    metrics.alertsBySeverity[severity]++;
    const proto = alert.protocol;
    metrics.alertsByProtocol[proto] = (metrics.alertsByProtocol[proto] || 0) + 1;
    metrics.alertsBySourceIP[alert.source_ip] = (metrics.alertsBySourceIP[alert.source_ip] || 0) + 1;
    metrics.alertsByDestIP[alert.dest_ip] = (metrics.alertsByDestIP[alert.dest_ip] || 0) + 1;
    metrics.topSignatures[alert.signature] = (metrics.topSignatures[alert.signature] || 0) + 1;
    metrics.recentAlerts.unshift(alert);
    if (metrics.recentAlerts.length > 100) metrics.recentAlerts.pop();
    
    // Update timeline
    const hourStr = `${hour.toString().padStart(2, '0')}:00`;
    const existingHour = metrics.alertsTimeline.find(h => h.hour === hourStr);
    if (existingHour) {
      existingHour.count++;
    } else {
      metrics.alertsTimeline.push({ hour: hourStr, count: 1 });
    }
    // Keep only last 24 hours
    if (metrics.alertsTimeline.length > 24) {
      metrics.alertsTimeline.shift();
    }
    
    io.emit('newAlert', alert);
    console.log(`Alerta: ${severity.toUpperCase()} - ${alert.signature}`);
  }, 300000);
  
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

// API: Test - inyectar alerta falsa
app.get('/api/test/:severity', (req, res) => {
  const severity = req.params.severity;
  const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
  
  if (!validSeverities.includes(severity)) {
    return res.status(400).json({ error: 'Severidad inválida. Usa: critical, high, medium, low, info' });
  }
  
  const alert = {
    timestamp: new Date().toISOString(),
    severity: severity,
    signature: `TEST ALERT - ${severity.toUpperCase()} - ${Date.now()}`,
    source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
    source_port: Math.floor(Math.random() * 65535),
    dest_ip: `10.0.0.${Math.floor(Math.random() * 255)}`,
    dest_port: [80, 443, 22, 3389][Math.floor(Math.random() * 4)],
    protocol: ['TCP', 'UDP', 'HTTP'][Math.floor(Math.random() * 3)]
  };
  
  metrics.totalAlerts++;
  metrics.alertsBySeverity[severity]++;
  metrics.alertsByProtocol[alert.protocol] = metrics.alertsByProtocol[alert.protocol] || 0;
  metrics.alertsByProtocol[alert.protocol]++;
  metrics.alertsBySourceIP[alert.source_ip] = (metrics.alertsBySourceIP[alert.source_ip] || 0) + 1;
  metrics.alertsByDestIP[alert.dest_ip] = (metrics.alertsByDestIP[alert.dest_ip] || 0) + 1;
  metrics.topSignatures[alert.signature] = (metrics.topSignatures[alert.signature] || 0) + 1;
  metrics.recentAlerts.unshift(alert);
  if (metrics.recentAlerts.length > 100) metrics.recentAlerts.pop();
  
  // Update timeline
  const hour = new Date().getHours();
  const hourStr = `${hour.toString().padStart(2, '0')}:00`;
  const existingHour = metrics.alertsTimeline.find(h => h.hour === hourStr);
  if (existingHour) {
    existingHour.count++;
  } else {
    metrics.alertsTimeline.push({ hour: hourStr, count: 1 });
  }
  
  io.emit('newAlert', alert);
  
  res.json({ success: true, alert });
});

// API: Reiniciar métricas
app.post('/api/reset', (req, res) => {
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

// WebSocket: Enviar actualizaciones en tiempo real
io.on('connection', (socket) => {
  console.log('Cliente conectado');

  // Enviar métricas iniciales
  socket.emit('metrics', {
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

  socket.on('disconnect', () => {
    console.log('Cliente desconectado');
  });
});

server.listen(PORT, () => {
  console.log(`Dashboard de Suricata ejecutándose en http://localhost:${PORT}`);
});
