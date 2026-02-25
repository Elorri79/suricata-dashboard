// Suricata Dashboard - Main Application

// Inicializar Socket.IO
const socket = io();

// Referencias DOM
const elements = {
  connectionStatus: document.getElementById('connection-status'),
  currentTime: document.getElementById('current-time'),
  totalAlerts: document.getElementById('total-alerts'),
  criticalCount: document.getElementById('critical-count'),
  highCount: document.getElementById('high-count'),
  mediumCount: document.getElementById('medium-count'),
  lowCount: document.getElementById('low-count'),
  infoCount: document.getElementById('info-count'),
  signatureList: document.getElementById('signature-list'),
  sourceIPList: document.getElementById('source-ip-list'),
  destIPList: document.getElementById('dest-ip-list'),
  alertsTableBody: document.getElementById('alerts-table-body'),
  alertSearch: document.getElementById('alert-search'),
  toastContainer: document.getElementById('toast-container'),
  androidStatusText: document.getElementById('android-status-text'),
  apsValue: document.getElementById('aps-value'),
  suriAvatar: document.getElementById('suri-avatar'),
  avatarVideo: document.getElementById('avatar-video'),
  speechText: document.getElementById('speech-text'),
  speechMeta: document.getElementById('speech-meta'),
  speechContent: document.getElementById('speech-content'),
  threatLevel: document.getElementById('threat-level-text'),
  alertsPerMin: document.getElementById('alerts-per-min'),
  threatFill: document.getElementById('threat-fill'),
  threatValue: document.getElementById('threat-value'),
  systemPulse: document.getElementById('system-pulse'),
  matrixBg: document.getElementById('matrix-bg')
};

// Matrix Rain Effect
function initMatrix() {
  const canvas = elements.matrixBg;
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  
  const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
  const fontSize = 14;
  const columns = Math.floor(canvas.width / fontSize);
  const drops = Array(columns).fill(1);
  
  function draw() {
    ctx.fillStyle = 'rgba(2, 5, 7, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    ctx.fillStyle = '#00e5ff';
    ctx.font = fontSize + 'px monospace';
    
    for (let i = 0; i < drops.length; i++) {
      const char = chars[Math.floor(Math.random() * chars.length)];
      const x = i * fontSize;
      const y = drops[i] * fontSize;
      
      ctx.fillStyle = `rgba(0, 229, 255, ${Math.random() * 0.5 + 0.1})`;
      ctx.fillText(char, x, y);
      
      if (y > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }
  
  setInterval(draw, 50);
  
  window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  });
}

// Threat Level Calculator
function calculateThreatLevel(data) {
  const critical = data.alertsBySeverity?.critical || 0;
  const high = data.alertsBySeverity?.high || 0;
  const medium = data.alertsBySeverity?.medium || 0;
  const low = data.alertsBySeverity?.low || 0;
  const total = data.totalAlerts || 0;
  
  if (total === 0) return { level: 'LOW', percent: 5, class: '' };
  
  const threatScore = (critical * 100) + (high * 50) + (medium * 20) + (low * 5);
  const maxScore = Math.max(total * 10, 100);
  const percent = Math.min(Math.round((threatScore / maxScore) * 100), 100);
  
  let level, className;
  if (percent >= 75) {
    level = 'CRITICAL';
    className = 'critical';
  } else if (percent >= 50) {
    level = 'HIGH';
    className = 'high';
  } else if (percent >= 25) {
    level = 'MEDIUM';
    className = 'medium';
  } else {
    level = 'LOW';
    className = '';
  }
  
  return { level, percent, class: className };
}

function updateThreatLevel(data) {
  if (!elements.threatFill || !elements.threatValue) return;
  
  const threat = calculateThreatLevel(data);
  
  elements.threatFill.style.width = threat.percent + '%';
  elements.threatFill.className = 'threat-fill ' + threat.class;
  elements.threatValue.textContent = threat.level;
  elements.threatValue.className = 'threat-value ' + threat.class;
  
  if (threat.class === 'critical' || threat.class === 'high') {
    elements.systemPulse?.classList.add('alert');
    document.body.classList.add('alert-flash');
    setTimeout(() => document.body.classList.remove('alert-flash'), 300);
  } else {
    elements.systemPulse?.classList.remove('alert');
  }
}

// APS tracking
let alertTimestamps = [];
const MAX_APS_SAMPLES = 60; // track last 60 seconds

// Colores para gráficos - Cyberpunk Neon
const chartColors = {
  critical: '#ff0044',
  high: '#ff6600',
  medium: '#ffee00',
  low: '#00ff88',
  info: '#8800ff',
  tcp: '#00f0ff',
  udp: '#ff00ff',
  icmp: '#00ff88',
  http: '#ff6600',
  https: '#ffee00',
  dns: '#ff0044',
  timeline: '#00f0ff'
};

// Instancias de gráficos
let severityChart, protocolChart, timelineChart;

// Alertas para filtrado
let allAlerts = [];

document.addEventListener('DOMContentLoaded', () => {
  initMatrix();
  initCharts();
  initEventListeners();
  initSuriAvatar();
  updateTime();
  setInterval(updateTime, 1000);
  setInterval(updateAPS, 1000);
  connectSocket();
  
  // Polling periódico: refrescar métricas cada 10 segundos
  setInterval(() => {
    fetch('/api/metrics')
      .then(res => res.json())
      .then(data => updateDashboard(data))
      .catch(err => console.error('Polling error:', err));
  }, 10000);
  
  setTimeout(() => {
    if (severityChart) severityChart.update();
    if (protocolChart) protocolChart.update();
    if (timelineChart) timelineChart.update();
  }, 100);
});

// ─── Video state machine ────────────────────────────────────────────────
// El video tiene ~6s. Estructura:
//   0.0 – 1.2s : arranque con "salto" → SALTAMOS
//   1.2 – 2.0s : posición estable, sin movimiento boca  → IDLE loop
//   2.0 – 6.0s : boca en movimiento                     → TALKING loop
const VIDEO_IDLE_START = 1.2;
const VIDEO_IDLE_END = 2.0;
const VIDEO_TALK_START = 2.0;
const VIDEO_TALK_END = 6.0;

const videoState = {
  mode: 'idle',      // 'idle' | 'talking'
  loopHandler: null,  // referencia al listener de timeupdate activo
  currentVideo: null  // video actualmente cargado
};

function getVideoForSeverity(severity) {
  if (severity === 'critical') return '/videos/critical.mp4';
  if (severity === 'low' || severity === 'info') return '/videos/ok.mp4';
  return '/videos/medium.mp4';
}

function changeVideo(severity) {
  const video = elements.avatarVideo;
  if (!video) return;
  
  const newSrc = getVideoForSeverity(severity);
  if (videoState.currentVideo === newSrc) return;
  
  videoState.currentVideo = newSrc;
  video.src = newSrc;
  video.load();
}

function setVideoLoop(startTime, endTime) {
  const video = elements.avatarVideo;
  if (!video) return;

  // Quitar handler anterior
  if (videoState.loopHandler) {
    video.removeEventListener('timeupdate', videoState.loopHandler);
    videoState.loopHandler = null;
  }

  // Saltar al inicio de la sección si estamos fuera de rango
  if (video.currentTime < startTime || video.currentTime >= endTime) {
    video.currentTime = startTime;
  }

  // Nuevo handler de loop
  const handler = () => {
    if (video.currentTime >= endTime) {
      video.currentTime = startTime;
    }
  };
  videoState.loopHandler = handler;
  video.addEventListener('timeupdate', handler);

  video.play().catch(() => { });
}

function setVideoIdle(force = false) {
  if (!force && videoState.mode === 'idle') return;
  videoState.mode = 'idle';
  setVideoLoop(VIDEO_IDLE_START, VIDEO_IDLE_END);
}

function setVideoTalking() {
  videoState.mode = 'talking';
  setVideoLoop(VIDEO_TALK_START, VIDEO_TALK_END);
}
// ────────────────────────────────────────────────────────────────────────

// Initialize SURI Video Avatar
function initSuriAvatar() {
  const speechText = document.getElementById('speech-text');
  const speechMeta = document.getElementById('speech-meta');
  if (speechText) speechText.textContent = 'System ready. All sensors online.';
  if (speechMeta) speechMeta.textContent = 'Awaiting threat data';

  // Borde idle por defecto
  setAvatarSeverity('idle');

  const video = elements.avatarVideo;
  if (!video) return;

  video.muted = true;
  video.loop = false;
  video.playsInline = true;
  videoState.currentVideo = '/videos/ok.mp4';

  video.addEventListener('loadedmetadata', () => {
    video.currentTime = VIDEO_IDLE_START;
    setVideoIdle(true);
  });

  video.addEventListener('canplay', () => {
    if (videoState.mode === 'idle' && video.paused) setVideoLoop(VIDEO_IDLE_START, VIDEO_IDLE_END);
  }, { once: true });

  // Reanudar si autoplay fue bloqueado
  const resumeOnInteraction = () => {
    if (video.paused) video.play().catch(() => { });
    document.removeEventListener('click', resumeOnInteraction);
    document.removeEventListener('keydown', resumeOnInteraction);
  };
  document.addEventListener('click', resumeOnInteraction);
  document.addEventListener('keydown', resumeOnInteraction);

  // Fallback SVG si el video falla
  video.addEventListener('error', () => {
    console.warn('Avatar video failed to load, showing placeholder');
    if (elements.suriAvatar) {
      elements.suriAvatar.innerHTML = `
        <div class="avatar-fallback">
          <svg viewBox="0 0 100 120" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="faceGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#1a2a3a"/>
                <stop offset="100%" stop-color="#050a0f"/>
              </linearGradient>
            </defs>
            <ellipse cx="50" cy="65" rx="38" ry="46" fill="url(#faceGrad)" stroke="#00e5ff" stroke-width="1.5" opacity="0.9"/>
            <rect x="8" y="68" width="8" height="20" rx="4" fill="#101820" stroke="#00e5ff" stroke-width="1" opacity="0.7"/>
            <rect x="84" y="68" width="8" height="20" rx="4" fill="#101820" stroke="#00e5ff" stroke-width="1" opacity="0.7"/>
            <line x1="34" y1="19" x2="28" y2="6" stroke="#00e5ff" stroke-width="2" opacity="0.8"/>
            <circle cx="28" cy="5" r="3" fill="#ff003c"><animate attributeName="opacity" values="1;0.3;1" dur="1.2s" repeatCount="indefinite"/></circle>
            <line x1="66" y1="19" x2="72" y2="6" stroke="#00e5ff" stroke-width="2" opacity="0.8"/>
            <circle cx="72" cy="5" r="3" fill="#ff003c"><animate attributeName="opacity" values="1;0.3;1" dur="0.9s" repeatCount="indefinite"/></circle>
            <ellipse cx="36" cy="62" rx="9" ry="11" fill="#00e5ff" opacity="0.9">
              <animate attributeName="ry" values="11;1;11" dur="4s" keyTimes="0;0.48;0.5" repeatCount="indefinite"/>
            </ellipse>
            <ellipse cx="64" cy="62" rx="9" ry="11" fill="#00e5ff" opacity="0.9">
              <animate attributeName="ry" values="11;1;11" dur="4s" keyTimes="0;0.48;0.5" repeatCount="indefinite"/>
            </ellipse>
            <ellipse cx="39" cy="58" rx="3" ry="4" fill="white" opacity="0.4"/>
            <ellipse cx="67" cy="58" rx="3" ry="4" fill="white" opacity="0.4"/>
            <line x1="38" y1="92" x2="62" y2="92" stroke="#00e5ff" stroke-width="3" stroke-linecap="round" opacity="0.8"/>
            <ellipse cx="50" cy="55" rx="30" ry="35" fill="rgba(0,229,255,0.04)"/>
          </svg>
          <div class="avatar-fallback-scan"></div>
        </div>
      `;
    }
  });

  // Arranque inmediato si el video ya está listo (cargado previamente)
  if (video.readyState >= 2) {
    video.currentTime = VIDEO_IDLE_START;
    setVideoIdle(true);  // force=true para garantizar que se instala el handler
  }
  
  // Parallax effect on mouse move
  const avatarFrame = elements.suriAvatar;
  if (avatarFrame) {
    document.addEventListener('mousemove', (e) => {
      const rect = avatarFrame.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      
      const tiltX = y * 0.02;
      const tiltY = -x * 0.02;
      
      avatarFrame.style.transform = `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg)`;
    });
    
    document.addEventListener('mouseleave', () => {
      avatarFrame.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg)';
    });
  }
}

// Gráficos
function initCharts() {
  Chart.defaults.color = '#6a8fa8';
  Chart.defaults.font.family = 'JetBrains Mono';

  // Severity Chart (Doughnut)
  const severityCtx = document.getElementById('severity-chart').getContext('2d');
  severityChart = new Chart(severityCtx, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: [
          chartColors.critical + 'cc',
          chartColors.high + 'cc',
          chartColors.medium + 'cc',
          chartColors.low + 'cc',
          chartColors.info + 'cc'
        ],
        borderColor: [
          chartColors.critical,
          chartColors.high,
          chartColors.medium,
          chartColors.low,
          chartColors.info
        ],
        borderWidth: 2,
        hoverOffset: 10
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#6a8fa8',
            padding: 10,
            usePointStyle: true,
            pointStyle: 'rectRounded',
            font: { family: 'JetBrains Mono', size: 10 }
          }
        },
        tooltip: {
          backgroundColor: '#0a0f14',
          borderColor: '#00f0ff',
          borderWidth: 1,
          titleColor: '#00f0ff',
          bodyColor: '#e0f0ff',
          padding: 10,
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw.toLocaleString('es-ES')} (${((ctx.raw / (ctx.dataset.data.reduce((a, b) => a + b, 0) || 1)) * 100).toFixed(1)}%)`
          }
        }
      }
    }
  });

  // Protocol Chart (Doughnut)
  const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
  protocolChart = new Chart(protocolCtx, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'],
      datasets: [{
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: [
          chartColors.tcp + 'cc',
          chartColors.udp + 'cc',
          chartColors.icmp + 'cc',
          chartColors.http + 'cc',
          chartColors.https + 'cc',
          chartColors.dns + 'cc'
        ],
        borderColor: [
          chartColors.tcp,
          chartColors.udp,
          chartColors.icmp,
          chartColors.http,
          chartColors.https,
          chartColors.dns
        ],
        borderWidth: 2,
        hoverOffset: 10
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#6a8fa8',
            padding: 10,
            usePointStyle: true,
            pointStyle: 'rectRounded',
            font: { family: 'JetBrains Mono', size: 10 }
          }
        },
        tooltip: {
          backgroundColor: '#0a0f14',
          borderColor: '#00f0ff',
          borderWidth: 1,
          titleColor: '#00f0ff',
          bodyColor: '#e0f0ff',
          padding: 10,
          callbacks: {
            label: (ctx) => ` ${ctx.label}: ${ctx.raw.toLocaleString('es-ES')} (${((ctx.raw / (ctx.dataset.data.reduce((a, b) => a + b, 0) || 1)) * 100).toFixed(1)}%)`
          }
        }
      }
    }
  });

  // Timeline Chart (Line)
  const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
  timelineChart = new Chart(timelineCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'ALERTS/HOUR',
        data: [],
        borderColor: chartColors.timeline,
        backgroundColor: (ctx) => {
          const gradient = ctx.chart.ctx.createLinearGradient(0, 0, 0, ctx.chart.height);
          gradient.addColorStop(0, 'rgba(0, 240, 255, 0.3)');
          gradient.addColorStop(1, 'rgba(0, 240, 255, 0.0)');
          return gradient;
        },
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 7,
        pointBackgroundColor: chartColors.timeline,
        pointBorderColor: '#030508',
        pointBorderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        intersect: false,
        mode: 'index'
      },
      scales: {
        x: {
          grid: {
            color: 'rgba(0, 240, 255, 0.07)',
            drawBorder: false
          },
          ticks: {
            color: '#6a8fa8',
            font: { family: 'JetBrains Mono', size: 10 },
            maxTicksLimit: 12
          }
        },
        y: {
          beginAtZero: true,
          grid: {
            color: 'rgba(0, 240, 255, 0.07)',
            drawBorder: false
          },
          ticks: {
            color: '#6a8fa8',
            font: { family: 'JetBrains Mono', size: 10 }
          }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0a0f14',
          borderColor: '#00f0ff',
          borderWidth: 1,
          titleColor: '#00f0ff',
          bodyColor: '#e0f0ff',
          padding: 10
        }
      }
    }
  });
}

// Event Listeners
function initEventListeners() {
  elements.alertSearch.addEventListener('input', filterAlerts);
}

// Socket Connection
function connectSocket() {
  socket.on('connect', () => {
    elements.connectionStatus.textContent = 'ONLINE';
    elements.connectionStatus.style.color = '#00ff88';
    elements.connectionStatus.parentElement.querySelector('.pulse').style.background = '#00ff88';
  });

  socket.on('disconnect', () => {
    elements.connectionStatus.textContent = 'OFFLINE';
    elements.connectionStatus.style.color = '#ff0044';
    elements.connectionStatus.parentElement.querySelector('.pulse').style.background = '#ff0044';
  });

  socket.on('metrics', (data) => {
    updateDashboard(data);
  });

  socket.on('newAlert', (alert) => {
    handleNewAlert(alert);
  });
}

// Actualizar Dashboard
function updateDashboard(data) {
  // Actualizar contadores con animación
  animateValue(elements.totalAlerts, parseInt(elements.totalAlerts.textContent.replace(/\./g, '').replace(/,/g, '')) || 0, data.totalAlerts, 400);
  animateValue(elements.criticalCount, parseInt(elements.criticalCount.textContent.replace(/\./g, '').replace(/,/g, '')) || 0, data.alertsBySeverity.critical, 400);
  animateValue(elements.highCount, parseInt(elements.highCount.textContent.replace(/\./g, '').replace(/,/g, '')) || 0, data.alertsBySeverity.high, 400);
  animateValue(elements.mediumCount, parseInt(elements.mediumCount.textContent.replace(/\./g, '').replace(/,/g, '')) || 0, data.alertsBySeverity.medium, 400);
  animateValue(elements.lowCount, parseInt(elements.lowCount.textContent.replace(/\./g, '').replace(/,/g, '')) || 0, data.alertsBySeverity.low, 400);
  animateValue(elements.infoCount, parseInt(elements.infoCount.textContent.replace(/\./g, '').replace(/,/g, '')) || 0, data.alertsBySeverity.info, 400);

  // Actualizar nivel de amenaza
  updateThreatLevel(data);
  
  // Actualizar gráficos
  updateSeverityChart(data.alertsBySeverity);
  updateProtocolChart(data.alertsByProtocol);
  updateTimelineChart(data.alertsTimeline);

  // Actualizar listas
  updateSignatureList(data.topSignatures);
  updateIPList(elements.sourceIPList, data.topSourceIPs);
  updateIPList(elements.destIPList, data.topDestIPs);

  // Actualizar alertas recientes en memoria si aún no las tenemos
  if (data.recentAlerts && allAlerts.length === 0) {
    allAlerts = data.recentAlerts;
  }

  // Actualizar speech bubble
  if (data.recentAlerts && data.recentAlerts.length > 0) {
    updateSpeechBubble(data.recentAlerts[0]);
  }

  // Actualizar tabla
  if (!elements.alertSearch.value) {
    updateAlertsTable(data.recentAlerts || []);
  }
}

// Manejar nueva alerta
function handleNewAlert(alert) {
  const now = Date.now();
  alertTimestamps.push(now);

  // Mantener solo últimos 60 segundos
  alertTimestamps = alertTimestamps.filter(t => now - t <= 60000);

  // Agregar a lista de alertas locales
  allAlerts.unshift(alert);
  if (allAlerts.length > 200) allAlerts.pop();

  // Mostrar toast solo si es alta o crítica
  if (alert.severity === 'critical' || alert.severity === 'high') {
    showToast(alert);
  }

  // Actualizar tabla si no hay filtro
  if (!elements.alertSearch.value) {
    updateAlertsTable(allAlerts.slice(0, 50));
  }

  // Solicitar métricas actualizadas del servidor
  fetch('/api/metrics')
    .then(res => res.json())
    .then(data => {
      updateDashboard(data);
    })
    .catch(err => console.error('Error fetching metrics:', err));
}

// Calcular y mostrar APS (Alerts Per Second)
function updateAPS() {
  const now = Date.now();
  const last10s = alertTimestamps.filter(t => now - t <= 10000);
  const aps = (last10s.length / 10).toFixed(1);
  if (elements.apsValue) {
    elements.apsValue.textContent = aps;
    elements.apsValue.classList.toggle('high-aps', parseFloat(aps) > 1);
  }
  // Alertas por minuto
  const last60s = alertTimestamps.filter(t => now - t <= 60000);
  if (elements.alertsPerMin) {
    elements.alertsPerMin.textContent = last60s.length;
  }
}

// Gráficos
function updateSeverityChart(severityData) {
  if (!severityChart) return;
  severityChart.data.datasets[0].data = [
    severityData.critical || 0,
    severityData.high || 0,
    severityData.medium || 0,
    severityData.low || 0,
    severityData.info || 0
  ];
  severityChart.update();
}

function updateProtocolChart(protocolData) {
  if (!protocolChart) return;
  protocolChart.data.datasets[0].data = [
    protocolData.TCP || 0,
    protocolData.UDP || 0,
    protocolData.ICMP || 0,
    protocolData.HTTP || 0,
    protocolData.HTTPS || 0,
    protocolData.DNS || 0
  ];
  protocolChart.update();
}

function updateTimelineChart(timelineData) {
  if (!timelineChart) return;
  if (!timelineData || timelineData.length === 0) {
    timelineChart.data.labels = [];
    timelineChart.data.datasets[0].data = [];
    timelineChart.update();
    return;
  }
  timelineChart.data.labels = timelineData.map(d => d.hour);
  timelineChart.data.datasets[0].data = timelineData.map(d => d.count);
  timelineChart.update();
}

// Listas
function updateSignatureList(signatures) {
  if (!signatures || signatures.length === 0) {
    elements.signatureList.innerHTML = '<li class="empty-state">WAITING FOR DATA...</li>';
    return;
  }

  const maxCount = signatures[0]?.count || 1;
  elements.signatureList.innerHTML = signatures.map((sig, i) => {
    const pct = Math.round((sig.count / maxCount) * 100);
    const rank = i + 1;
    return `
    <li>
      <div class="sig-rank">${rank < 10 ? '0' + rank : rank}</div>
      <div class="sig-info">
        <span class="signature-name" title="${escapeHtml(sig.signature)}">${escapeHtml(sig.signature)}</span>
        <div class="sig-bar-wrap"><div class="sig-bar" style="width:${pct}%"></div></div>
      </div>
      <span class="signature-count">${sig.count.toLocaleString('es-ES')}</span>
    </li>
  `;
  }).join('');
}

function updateIPList(container, ips) {
  if (!ips || ips.length === 0) {
    container.innerHTML = '<li class="empty-state">WAITING FOR DATA...</li>';
    return;
  }
  const maxCount = ips[0]?.count || 1;
  container.innerHTML = ips.map((ip, i) => {
    const pct = Math.round((ip.count / maxCount) * 100);
    return `
    <li>
      <div class="sig-rank">${(i + 1).toString().padStart(2, '0')}</div>
      <div class="sig-info">
        <span class="signature-name">${ip.ip}</span>
        <div class="sig-bar-wrap"><div class="sig-bar ip-bar" style="width:${pct}%"></div></div>
      </div>
      <span class="ip-count">${ip.count.toLocaleString('es-ES')}</span>
    </li>
  `;
  }).join('');
}

// Tabla de alertas
function updateAlertsTable(alerts) {
  if (!alerts || alerts.length === 0) {
    elements.alertsTableBody.innerHTML = '<tr class="empty-state"><td colspan="8">NO THREATS DETECTED</td></tr>';
    return;
  }

  elements.alertsTableBody.innerHTML = alerts.slice(0, 60).map(alert => `
    <tr class="alert-row-${alert.severity || 'info'}">
      <td class="ts-cell">${formatTimestamp(alert.timestamp)}</td>
      <td><span class="severity-badge ${alert.severity || 'null'}">${(alert.severity || 'N/A').toUpperCase()}</span></td>
      <td class="sig-cell" title="${escapeHtml(alert.signature || '')}">${escapeHtml(truncate(alert.signature || 'N/A', 55))}</td>
      <td class="ip-cell">${alert.source_ip || '-'}</td>
      <td class="port-cell">${alert.source_port || '-'}</td>
      <td class="ip-cell">${alert.dest_ip || '-'}</td>
      <td class="port-cell">${alert.dest_port || '-'}</td>
      <td><span class="proto-badge">${alert.protocol || '-'}</span></td>
    </tr>
  `).join('');
}

// Filtrar alertas
function filterAlerts() {
  const query = elements.alertSearch.value.toLowerCase().trim();
  if (!query) {
    updateAlertsTable(allAlerts.slice(0, 50));
    return;
  }
  const filtered = allAlerts.filter(alert => {
    const signature = (alert.signature || '').toLowerCase();
    const sourceIP = (alert.source_ip || '').toLowerCase();
    const destIP = (alert.dest_ip || '').toLowerCase();
    const severity = (alert.severity || '').toLowerCase();
    const protocol = (alert.protocol || '').toLowerCase();
    return signature.includes(query) || sourceIP.includes(query) || destIP.includes(query) || severity.includes(query) || protocol.includes(query);
  });
  updateAlertsTable(filtered.slice(0, 60));
}

// Toast (solo para alertas críticas/altas)
function showToast(alert) {
  // Limitar toasts en pantalla
  const existingToasts = elements.toastContainer.querySelectorAll('.toast');
  if (existingToasts.length >= 4) {
    existingToasts[0].remove();
  }

  const toast = document.createElement('div');
  toast.className = `toast ${alert.severity || 'info'}`;
  toast.innerHTML = `
    <div class="toast-icon">${alert.severity === 'critical' ? '⚠' : '!'}</div>
    <div class="toast-body">
      <div class="toast-header">
        <span class="severity-badge ${alert.severity || 'null'}">${(alert.severity || 'UNKNOWN').toUpperCase()}</span>
        <span class="toast-time">${formatTimestamp(alert.timestamp)}</span>
      </div>
      <div class="toast-signature">${escapeHtml(truncate(alert.signature || 'UNKNOWN SIGNATURE', 60))}</div>
      <div class="toast-ips">${alert.source_ip || '?'} → ${alert.dest_ip || '?'}</div>
    </div>
  `;
  elements.toastContainer.appendChild(toast);

  // Update android status
  updateAndroidStatus(alert.severity);

  // Update speech bubble
  updateSpeechBubble(alert);

  setTimeout(() => {
    toast.classList.add('fadeout');
    setTimeout(() => toast.remove(), 400);
  }, 6000);
}

// Messages by severity
const faceMessages = {
  critical: '⚠ CRITICAL THREAT DETECTED',
  high: '! HIGH SEVERITY ALERT',
  medium: '> ANALYZING ANOMALY',
  low: '> SCANNING ACTIVITY',
  info: '> MONITORING NETWORK'
};

let androidTimeout;
let dialogueTimeout;

// ÚNICA definición de updateAndroidStatus (bug fix: eliminada duplicación)
function updateAndroidStatus(severity) {
  const statusText = elements.androidStatusText;
  const statusDot = document.getElementById('android-status-dot');

  if (!statusText) return;

  const colorMap = {
    critical: chartColors.critical,
    high: chartColors.high,
    medium: chartColors.medium,
    low: chartColors.low,
    info: chartColors.timeline
  };

  const dotClassMap = {
    critical: 'status-dot-mini alert',
    high: 'status-dot-mini warning',
    medium: 'status-dot-mini',
    low: 'status-dot-mini safe',
    info: 'status-dot-mini'
  };

  statusText.textContent = faceMessages[severity] || faceMessages.info;
  statusText.style.color = colorMap[severity] || colorMap.info;
  if (statusDot) statusDot.className = dotClassMap[severity] || dotClassMap.info;

  // Reset a normal después de timeout
  clearTimeout(androidTimeout);
  androidTimeout = setTimeout(() => {
    if (statusText) {
      statusText.textContent = 'SURI ONLINE';
      statusText.style.color = chartColors.timeline;
    }
    if (statusDot) statusDot.className = 'status-dot-mini safe';
  }, 6000);
}

// Speech Bubble Update
function updateSpeechBubble(alert) {
  const speechBubble = document.querySelector('.speech-bubble');
  if (!speechBubble || !alert) return;

  const speechText = document.getElementById('speech-text');
  const speechMeta = document.getElementById('speech-meta');

  if (speechText) {
    speechText.textContent = truncate(alert.signature || 'UNKNOWN SIGNATURE', 60);
  }
  if (speechMeta) {
    speechMeta.textContent = `${alert.source_ip || '?'}:${alert.source_port || '?'} → ${alert.dest_ip || '?'}:${alert.dest_port || '?'} [${alert.protocol || '-'}]`;
  }

  const severity = alert.severity || 'info';
  speechBubble.className = `speech-bubble compact ${severity}`;

  playSuriTalking(severity);
}

// Actualizar solo el color del borde del avatar según severidad
function setAvatarSeverity(severity) {
  if (!elements.suriAvatar) return;
  // Eliminar todas las clases de severidad anteriores
  elements.suriAvatar.classList.remove(
    'sev-idle', 'sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info'
  );
  elements.suriAvatar.classList.add(`sev-${severity}`);
}

// Activar modo talking en el video y poner borde del color de la severidad
function playSuriTalking(severity) {
  if (!elements.suriAvatar) return;

  setAvatarSeverity(severity || 'idle');

  changeVideo(severity || 'info');

  const video = elements.avatarVideo;
  if (video) {
    video.onloadeddata = () => {
      video.currentTime = VIDEO_TALK_START;
      setVideoTalking();
      video.onloadeddata = null;
    };
    video.load();
  }

  clearTimeout(dialogueTimeout);
  dialogueTimeout = setTimeout(() => {
    changeVideo('info');
    const video = elements.avatarVideo;
    if (video) {
      video.onloadeddata = () => {
        setVideoIdle();
        video.onloadeddata = null;
      };
      video.load();
    }
    setTimeout(() => setAvatarSeverity('idle'), 1000);
  }, 6000);
}

// Reiniciar métricas
async function resetMetrics() {
  try {
    await fetch('/api/reset', { method: 'POST' });
    allAlerts = [];
    alertTimestamps = [];
    showNotification('>> SYSTEM RESET COMPLETE');
  } catch (error) {
    showNotification('>> ERROR: RESET FAILED');
  }
}

// Notificación simple
function showNotification(message) {
  const toast = document.createElement('div');
  toast.className = 'toast info';
  toast.innerHTML = `<div class="toast-icon">i</div><div class="toast-body"><div class="toast-signature">${message}</div></div>`;
  elements.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('fadeout');
    setTimeout(() => toast.remove(), 400);
  }, 3000);
}

// Utilidades
function updateTime() {
  if (elements.currentTime) {
    elements.currentTime.textContent = new Date().toLocaleTimeString('es-ES', { hour12: false });
  }
}

function animateValue(element, start, end, duration) {
  if (!element || isNaN(start) || isNaN(end) || start === end) {
    if (element) element.textContent = formatNumber(end);
    return;
  }

  const range = end - start;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const value = Math.floor(start + range * easeOutQuad(progress));
    element.textContent = formatNumber(value);

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      element.textContent = formatNumber(end);
      element.classList.add('updated');
      setTimeout(() => element.classList.remove('updated'), 300);
    }
  }

  requestAnimationFrame(update);
}

function easeOutQuad(t) {
  return t * (2 - t);
}

function formatNumber(num) {
  return num.toLocaleString('es-ES');
}

function formatTimestamp(timestamp) {
  if (!timestamp) return '--:--:--';
  const date = new Date(timestamp);
  return date.toISOString().replace('T', ' ').substring(0, 19);
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function truncate(text, length) {
  if (!text) return '';
  return text.length > length ? text.substring(0, length) + '…' : text;
}
