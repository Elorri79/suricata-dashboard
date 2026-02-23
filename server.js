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
