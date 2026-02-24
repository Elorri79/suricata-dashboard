const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const LOG_FILE = process.env.SURICATA_LOG || '/mnt/suricata-logs/eve.json';

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

// Función para procesar una línea del archivo eve.json
function processAlert(line) {
  try {
    const event = JSON.parse(line);
    
    // Solo procesar eventos de tipo 'alert'
    if (event.event_type !== 'alert') return;
    
    const alert = event.alert;
    if (!alert) return;
    
    // Mapear severidad de Suricata (1=high, 2=medium, 3=low) a nuestro formato
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
    
    // Actualizar métricas
    metrics.totalAlerts++;
    metrics.alertsBySeverity[severity]++;
    
    const proto = processedAlert.protocol.toUpperCase();
    metrics.alertsByProtocol[proto] = (metrics.alertsByProtocol[proto] || 0) + 1;
    
    metrics.alertsBySourceIP[processedAlert.source_ip] = (metrics.alertsBySourceIP[processedAlert.source_ip] || 0) + 1;
    metrics.alertsByDestIP[processedAlert.dest_ip] = (metrics.alertsByDestIP[processedAlert.dest_ip] || 0) + 1;
    metrics.topSignatures[processedAlert.signature] = (metrics.topSignatures[processedAlert.signature] || 0) + 1;
    
    metrics.recentAlerts.unshift(processedAlert);
    if (metrics.recentAlerts.length > 100) metrics.recentAlerts.pop();
    
    // Update timeline
    const date = new Date(processedAlert.timestamp);
    const hour = date.getHours();
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
    
    metrics.lastUpdate = new Date().toISOString();
    
    // Enviar alerta en tiempo real a todos los clientes conectados
    io.emit('newAlert', processedAlert);
    console.log(`Alerta: ${severity.toUpperCase()} - ${processedAlert.signature}`);
    
  } catch (error) {
    // Ignorar líneas mal formateadas
  }
}

// Leer el archivo eve.json en tiempo real usando tail -f
function startTailing() {
  console.log(`Monitoreando archivo: ${LOG_FILE}`);
  
  // Verificar si el archivo existe
  if (!fs.existsSync(LOG_FILE)) {
    console.error(`ERROR: El archivo ${LOG_FILE} no existe`);
    console.log('Usando modo de prueba. Ejecuta: curl http://localhost:3000/api/test/start');
    return;
  }
  
  // Usar tail -f para leer nuevas líneas en tiempo real
  const tail = spawn('tail', ['-f', '-n', '0', LOG_FILE]);
  
  tail.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    lines.forEach(line => {
      if (line.trim()) {
        processAlert(line);
      }
    });
  });
  
  tail.stderr.on('data', (data) => {
    console.error(`Error en tail: ${data}`);
  });
  
  tail.on('close', (code) => {
    console.log(`tail process cerrado con código ${code}`);
    // Reintentar después de 5 segundos
    setTimeout(startTailing, 5000);
  });
}

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
  console.log(`Archivo de logs: ${LOG_FILE}`);
  
  // Iniciar monitoreo del archivo eve.json
  startTailing();
});
