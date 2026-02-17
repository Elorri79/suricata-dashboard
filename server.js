const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
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

// Procesar línea de log de Suricata
function processLogLine(line) {
  try {
    const event = JSON.parse(line.trim());
    if (!event.event_type) return null;

    const alert = {
      timestamp: event.timestamp || new Date().toISOString(),
      event_type: event.event_type,
      severity: null,
      signature: null,
      signature_id: null,
      source_ip: null,
      source_port: null,
      dest_ip: null,
      dest_port: null,
      protocol: null,
      app_proto: null
    };

    if (event.event_type === 'alert') {
      alert.severity = event.alert?.severity === 1 ? 'critical' :
                      event.alert?.severity === 2 ? 'high' :
                      event.alert?.severity === 3 ? 'medium' :
                      event.alert?.severity === 4 ? 'low' : 'info';
      alert.signature = event.alert?.signature;
      alert.signature_id = event.alert?.signature_id;
    }

    if (event.flow) {
      alert.protocol = event.flow?.proto?.toUpperCase();
    }

    if (event.src_ip) {
      alert.source_ip = event.src_ip;
      metrics.alertsBySourceIP[event.src_ip] = (metrics.alertsBySourceIP[event.src_ip] || 0) + 1;
    }

    if (event.dest_ip) {
      alert.dest_ip = event.dest_ip;
      metrics.alertsByDestIP[event.dest_ip] = (metrics.alertsByDestIP[event.dest_ip] || 0) + 1;
    }

    if (event.src_port) alert.source_port = event.src_port;
    if (event.dest_port) alert.dest_port = event.dest_port;
    if (event.app_proto) alert.app_proto = event.app_proto;

    // Actualizar contadores
    metrics.totalAlerts++;
    if (alert.severity) {
      metrics.alertsBySeverity[alert.severity]++;
    }
    if (alert.protocol) {
      metrics.alertsByProtocol[alert.protocol] = (metrics.alertsByProtocol[alert.protocol] || 0) + 1;
    }
    if (alert.signature) {
      metrics.topSignatures[alert.signature] = (metrics.topSignatures[alert.signature] || 0) + 1;
    }

    // Agregar a alertas recientes (max 100)
    metrics.recentAlerts.unshift(alert);
    if (metrics.recentAlerts.length > 100) {
      metrics.recentAlerts.pop();
    }

    return alert;
  } catch (e) {
    return null;
  }
}

// Generar datos de timeline (últimas 24 horas)
function generateTimeline() {
  const now = new Date();
  const timeline = [];

  for (let i = 23; i >= 0; i--) {
    const hour = new Date(now - i * 60 * 60 * 1000);
    const hourStr = hour.getHours().toString().padStart(2, '0') + ':00';
    timeline.push({
      hour: hourStr,
      count: Math.floor(Math.random() * 50) + (i < 2 ? 10 : 0)
    });
  }

  return timeline;
}

// API: Obtener métricas actuales
app.get('/api/metrics', (req, res) => {
  res.json({
    ...metrics,
    alertsTimeline: generateTimeline(),
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
    alertsTimeline: generateTimeline(),
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

// Generar alerta de prueba
function generateTestAlert() {
  const severities = ['low', 'medium', 'high', 'critical', 'info'];
  const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS'];
  const signatures = [
    'ET SCAN Potential SSH Scan OUTBOUND',
    'ET SCAN SMB Dialect Negotiation',
    'ET DNS Query for x86_64.microsoft.com',
    'GPL SMB 0x72 Buffer Overflow Attempt',
    'ET SCAN Nmap XMAS',
    'ET SCAN Null Scan',
    'ET ATTACK_RESPONSE ID gresquerade',
    'ET SCAN Sipvicious Scan',
    'ET POLICY Outbound Internal IP',
    'ET SCAN Port Sweep',
    'ET SCAN SYN Flood',
    'ET DNS Suspicious Long Domain',
    'ET SCAN Behavioral GeoIP Confirmed',
    'ET WEB_CLIENT Possible Adobe Flash',
    'ET SCAN Python CVE-2014-0160'
  ];

  return {
    timestamp: new Date().toISOString(),
    event_type: 'alert',
    severity: severities[Math.floor(Math.random() * severities.length)],
    signature: signatures[Math.floor(Math.random() * signatures.length)],
    signature_id: Math.floor(Math.random() * 2000000) + 2001000,
    source_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    source_port: Math.floor(Math.random() * 65535),
    dest_ip: '10.0.0.' + Math.floor(Math.random() * 255),
    dest_port: Math.floor(Math.random() * 65535),
    protocol: protocols[Math.floor(Math.random() * protocols.length)],
    app_proto: 'unknown'
  };
}

// Procesar alerta
function processAlert(alert) {
  metrics.totalAlerts++;
  metrics.alertsBySeverity[alert.severity]++;
  metrics.alertsByProtocol[alert.protocol] = (metrics.alertsByProtocol[alert.protocol] || 0) + 1;
  metrics.alertsBySourceIP[alert.source_ip] = (metrics.alertsBySourceIP[alert.source_ip] || 0) + 1;
  metrics.alertsByDestIP[alert.dest_ip] = (metrics.alertsByDestIP[alert.dest_ip] || 0) + 1;
  metrics.topSignatures[alert.signature] = (metrics.topSignatures[alert.signature] || 0) + 1;

  metrics.recentAlerts.unshift(alert);
  if (metrics.recentAlerts.length > 100) {
    metrics.recentAlerts.pop();
  }
}

// Generar datos históricos iniciales
function generateInitialData() {
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'];
  const signatures = [
    'ET SCAN Potential SSH Scan OUTBOUND',
    'ET SCAN SMB Dialect Negotiation',
    'ET DNS Query for x86_64.microsoft.com',
    'GPL SMB 0x72 Buffer Overflow Attempt',
    'ET SCAN Nmap XMAS',
    'ET SCAN Null Scan'
  ];

  // Generar 200 alertas históricas
  for (let i = 0; i < 200; i++) {
    const alert = {
      timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      event_type: 'alert',
      severity: severities[Math.floor(Math.random() * severities.length)],
      signature: signatures[Math.floor(Math.random() * signatures.length)],
      signature_id: Math.floor(Math.random() * 2000000) + 2001000,
      source_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      source_port: Math.floor(Math.random() * 65535),
      dest_ip: '10.0.0.' + Math.floor(Math.random() * 255),
      dest_port: Math.floor(Math.random() * 65535),
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      app_proto: 'unknown'
    };
    processAlert(alert);
  }

  // Generar timeline histórico
  metrics.alertsTimeline = [];
  for (let i = 23; i >= 0; i--) {
    const hour = new Date(Date.now() - i * 60 * 60 * 1000);
    const hourStr = hour.getHours().toString().padStart(2, '0') + ':00';
    metrics.alertsTimeline.push({
      hour: hourStr,
      count: Math.floor(Math.random() * 100) + 10
    });
  }

  console.log(`Datos iniciales generados: ${metrics.totalAlerts} alertas`);
}

// Generar datos históricos al inicio
generateInitialData();

// Simular eventos aleatorios cada 2 segundos (para demostración)
setInterval(() => {
  const alert = generateTestAlert();
  processAlert(alert);

  // Actualizar última hora del timeline
  metrics.alertsTimeline[metrics.alertsTimeline.length - 1].count++;

  // Enviar actualización por WebSocket
  io.emit('newAlert', alert);
  io.emit('metrics', {
    ...metrics,
    alertsTimeline: metrics.alertsTimeline,
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
}, 2000);

server.listen(PORT, () => {
  console.log(`Dashboard de Suricata ejecutándose en http://localhost:${PORT}`);
});
