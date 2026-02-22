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
  speechContent: document.getElementById('speech-content')
};

// APS tracking
let alertTimestamps = [];
const MAX_APS_SAMPLES = 10;

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

// Inicializar
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  initEventListeners();
  initSuriAvatar();
  updateTime();
  setInterval(updateTime, 1000);
  connectSocket();
});

// Initialize SURI Video Avatar
function initSuriAvatar() {
  const speechText = document.getElementById('speech-text');
  const speechMeta = document.getElementById('speech-meta');
  if (speechText) speechText.textContent = 'System ready...';
  if (speechMeta) speechMeta.textContent = 'Awaiting threat data';
  
  // Setup video avatar
  if (elements.avatarVideo) {
    elements.avatarVideo.addEventListener('loadedmetadata', () => {
      elements.avatarVideo.currentTime = 0;
    });
    elements.avatarVideo.play().catch(() => {
      console.log('Video autoplay blocked - user interaction required');
    });
  }
}

// Gráficos
function initCharts() {
  // Severity Chart (Doughnut)
  const severityCtx = document.getElementById('severity-chart').getContext('2d');
  severityChart = new Chart(severityCtx, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: [
          chartColors.critical,
          chartColors.high,
          chartColors.medium,
          chartColors.low,
          chartColors.info
        ],
        borderWidth: 2,
        borderColor: '#0a0f14',
        hoverOffset: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#6a8fa8',
            padding: 12,
            usePointStyle: true,
            pointStyle: 'rect',
            font: { family: 'JetBrains Mono', size: 10 }
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
          chartColors.tcp,
          chartColors.udp,
          chartColors.icmp,
          chartColors.http,
          chartColors.https,
          chartColors.dns
        ],
        borderWidth: 2,
        borderColor: '#0a0f14',
        hoverOffset: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#6a8fa8',
            padding: 12,
            usePointStyle: true,
            pointStyle: 'rect',
            font: { family: 'JetBrains Mono', size: 10 }
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
        label: 'ALERTS',
        data: [],
        borderColor: chartColors.timeline,
        backgroundColor: 'rgba(0, 240, 255, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.3,
        pointRadius: 3,
        pointHoverRadius: 6,
        pointBackgroundColor: chartColors.timeline,
        pointBorderColor: '#0a0f14',
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
            color: 'rgba(0, 240, 255, 0.1)',
            drawBorder: false
          },
          ticks: {
            color: '#6a8fa8',
            font: { family: 'JetBrains Mono', size: 10 }
          }
        },
        y: {
          beginAtZero: true,
          grid: {
            color: 'rgba(0, 240, 255, 0.1)',
            drawBorder: false
          },
          ticks: {
            color: '#6a8fa8',
            font: { family: 'JetBrains Mono', size: 10 }
          }
        }
      },
      plugins: {
        legend: {
          display: false
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
    elements.connectionStatus.parentElement.querySelector('.pulse').style.background = '#00ff88';
  });

  socket.on('disconnect', () => {
    elements.connectionStatus.textContent = 'OFFLINE';
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
  animateValue(elements.totalAlerts, parseInt(elements.totalAlerts.textContent), data.totalAlerts, 300);
  animateValue(elements.criticalCount, parseInt(elements.criticalCount.textContent), data.alertsBySeverity.critical, 300);
  animateValue(elements.highCount, parseInt(elements.highCount.textContent), data.alertsBySeverity.high, 300);
  animateValue(elements.mediumCount, parseInt(elements.mediumCount.textContent), data.alertsBySeverity.medium, 300);
  animateValue(elements.lowCount, parseInt(elements.lowCount.textContent), data.alertsBySeverity.low, 300);
  animateValue(elements.infoCount, parseInt(elements.infoCount.textContent), data.alertsBySeverity.info, 300);

  // Actualizar gráficos
  updateSeverityChart(data.alertsBySeverity);
  updateProtocolChart(data.alertsByProtocol);
  updateTimelineChart(data.alertsTimeline);

  // Actualizar listas
  updateSignatureList(data.topSignatures);
  updateIPList(elements.sourceIPList, data.topSourceIPs);
  updateIPList(elements.destIPList, data.topDestIPs);

  // Actualizar speech bubble con la última alerta
  if (data.recentAlerts && data.recentAlerts.length > 0) {
    updateSpeechBubble(data.recentAlerts[0]);
  }

  // Actualizar tabla
  updateAlertsTable(data.recentAlerts);
}

// Manejar nueva alerta
function handleNewAlert(alert) {
  // Track timestamp for APS
  const now = Date.now();
  alertTimestamps.push(now);

  // Remove old timestamps (older than 10 seconds)
  alertTimestamps = alertTimestamps.filter(t => now - t <= 10000);

  // Update APS display
  const aps = (alertTimestamps.length / 10).toFixed(1);
  elements.apsValue.textContent = aps;

  // Animate APS
  elements.apsValue.classList.add('updated');
  setTimeout(() => elements.apsValue.classList.remove('updated'), 200);

  // Mostrar toast
  showToast(alert);

  // Agregar a lista de alertas
  allAlerts.unshift(alert);
  if (allAlerts.length > 100) {
    allAlerts.pop();
  }

  // Actualizar tabla si no hay filtro
  if (!elements.alertSearch.value) {
    updateAlertsTable(allAlerts.slice(0, 50));
  }
}

// Gráficos
function updateSeverityChart(severityData) {
  severityChart.data.datasets[0].data = [
    severityData.critical || 0,
    severityData.high || 0,
    severityData.medium || 0,
    severityData.low || 0,
    severityData.info || 0
  ];
  severityChart.update('none');
}

function updateProtocolChart(protocolData) {
  protocolChart.data.datasets[0].data = [
    protocolData.TCP || 0,
    protocolData.UDP || 0,
    protocolData.ICMP || 0,
    protocolData.HTTP || 0,
    protocolData.HTTPS || 0,
    protocolData.DNS || 0
  ];
  protocolChart.update('none');
}

function updateTimelineChart(timelineData) {
  timelineChart.data.labels = timelineData.map(d => d.hour);
  timelineChart.data.datasets[0].data = timelineData.map(d => d.count);
  timelineChart.update('none');
}

// Listas
function updateSignatureList(signatures) {
  if (!signatures || signatures.length === 0) {
    elements.signatureList.innerHTML = '<li class="empty-state">WAITING FOR DATA...</li>';
    return;
  }

  elements.signatureList.innerHTML = signatures.map(sig => `
    <li>
      <span class="signature-name" title="${escapeHtml(sig.signature)}">${escapeHtml(sig.signature)}</span>
      <span class="signature-count">[${sig.count}]</span>
    </li>
  `).join('');
}

function updateIPList(container, ips) {
  if (!ips || ips.length === 0) {
    container.innerHTML = '<li class="empty-state">WAITING FOR DATA...</li>';
    return;
  }

  container.innerHTML = ips.map(ip => `
    <li>
      <span class="signature-name" title="${ip.ip}">${ip.ip}</span>
      <span class="ip-count">[${ip.count}]</span>
    </li>
  `).join('');
}

// Tabla de alertas
function updateAlertsTable(alerts) {
  if (!alerts || alerts.length === 0) {
    elements.alertsTableBody.innerHTML = '<tr class="empty-state"><td colspan="8">NO THREATS DETECTED</td></tr>';
    return;
  }

  elements.alertsTableBody.innerHTML = alerts.map(alert => `
    <tr>
      <td>${formatTimestamp(alert.timestamp)}</td>
      <td><span class="severity-badge ${alert.severity || 'null'}">${alert.severity || 'N/A'}</span></td>
      <td title="${escapeHtml(alert.signature || '')}">${truncate(alert.signature || 'N/A', 50)}</td>
      <td>${alert.source_ip || '-'}</td>
      <td>${alert.source_port || '-'}</td>
      <td>${alert.dest_ip || '-'}</td>
      <td>${alert.dest_port || '-'}</td>
      <td>${alert.protocol || '-'}</td>
    </tr>
  `).join('');
}

// Filtrar alertas
function filterAlerts() {
  const query = elements.alertSearch.value.toLowerCase();
  const filtered = allAlerts.filter(alert => {
    const signature = (alert.signature || '').toLowerCase();
    const sourceIP = (alert.source_ip || '').toLowerCase();
    const destIP = (alert.dest_ip || '').toLowerCase();
    return signature.includes(query) || sourceIP.includes(query) || destIP.includes(query);
  });
  updateAlertsTable(filtered.slice(0, 50));
}

// Toast
function showToast(alert) {
  const toast = document.createElement('div');
  toast.className = `toast ${alert.severity || 'info'}`;
  toast.innerHTML = `
    <span class="toast-time">${formatTimestamp(alert.timestamp)}</span>
    <div class="toast-message">
      <div><span class="severity-badge ${alert.severity || 'null'}">${(alert.severity || 'UNKNOWN').toUpperCase()}</span></div>
      <div class="toast-signature">${escapeHtml(alert.signature || 'UNKNOWN SIGNATURE')}</div>
    </div>
  `;
  elements.toastContainer.appendChild(toast);

  // Update android status based on alert severity
  updateAndroidStatus(alert.severity);

  // Update speech bubble
  updateSpeechBubble(alert);

  setTimeout(() => {
    toast.style.animation = 'slideIn 0.3s ease reverse';
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

// Android Face States - Now uses video avatar
const faceMessages = {
  critical: '!! DANGER !!',
  high: '!! WARNING !!',
  medium: '> ANALYZING',
  low: '> SCANNING',
  info: '> MONITORING'
};

let androidTimeout;
let currentFace = 'normal';
let dialogueTimeout;

function updateAndroidStatus(severity) {
  const statusText = elements.androidStatusText;
  const statusDot = document.getElementById('android-status-dot');

  if (!statusText) return;

  // Update status text based on severity
  if (severity === 'critical') {
    statusText.textContent = faceMessages.critical;
    statusText.style.color = chartColors.critical;
    if (statusDot) {
      statusDot.className = 'status-dot-mini alert';
    }
  } else if (severity === 'high') {
    statusText.textContent = faceMessages.high;
    statusText.style.color = chartColors.high;
    if (statusDot) {
      statusDot.className = 'status-dot-mini warning';
    }
  } else if (severity === 'medium') {
    statusText.textContent = faceMessages.medium;
    statusText.style.color = chartColors.medium;
    if (statusDot) {
      statusDot.className = 'status-dot-mini';
    }
  } else if (severity === 'low') {
    statusText.textContent = faceMessages.low;
    statusText.style.color = chartColors.low;
    if (statusDot) {
      statusDot.className = 'status-dot-mini safe';
    }
  } else {
    statusText.textContent = faceMessages.info;
    statusText.style.color = chartColors.timeline;
    if (statusDot) {
      statusDot.className = 'status-dot-mini';
    }
  }

  // Reset to normal after timeout
  clearTimeout(androidTimeout);
  androidTimeout = setTimeout(() => {
    if (statusText) {
      statusText.textContent = 'SURI ONLINE';
      statusText.style.color = chartColors.timeline;
    }
    if (statusDot) {
      statusDot.className = 'status-dot-mini';
    }
  }, 5000);
}

function updateAndroidStatus(severity) {
  const statusText = elements.androidStatusText;
  const statusDot = document.getElementById('android-status-dot');

  if (!statusText) return;

  // Update status text based on severity - video avatar doesn't have expressions
  if (severity === 'critical') {
    statusText.textContent = faceMessages.critical;
    statusText.style.color = chartColors.critical;
    if (statusDot) {
      statusDot.className = 'status-dot-mini alert';
    }
  } else if (severity === 'high') {
    statusText.textContent = faceMessages.high;
    statusText.style.color = chartColors.high;
    if (statusDot) {
      statusDot.className = 'status-dot-mini warning';
    }
  } else if (severity === 'medium') {
    statusText.textContent = faceMessages.medium;
    statusText.style.color = chartColors.medium;
    if (statusDot) {
      statusDot.className = 'status-dot-mini';
    }
  } else if (severity === 'low') {
    statusText.textContent = faceMessages.low;
    statusText.style.color = chartColors.low;
    if (statusDot) {
      statusDot.className = 'status-dot-mini safe';
    }
  } else {
    statusText.textContent = faceMessages.info;
    statusText.style.color = chartColors.timeline;
    if (statusDot) {
      statusDot.className = 'status-dot-mini';
    }
  }

  // Reset to normal after timeout
  clearTimeout(androidTimeout);
  androidTimeout = setTimeout(() => {
    if (statusText) {
      statusText.textContent = 'SURI ONLINE';
      statusText.style.color = chartColors.timeline;
    }
    if (statusDot) {
      statusDot.className = 'status-dot-mini';
    }
  }, 5000);
}

// Speech Bubble Update
function updateSpeechBubble(alert) {
  const speechBubble = document.querySelector('.speech-bubble');
  if (!speechBubble || !alert) return;

  const speechText = document.getElementById('speech-text');
  const speechMeta = document.getElementById('speech-meta');

  if (speechText) {
    speechText.textContent = truncate(alert.signature || 'UNKNOWN', 35);
  }
  if (speechMeta) {
    speechMeta.textContent = `${alert.source_ip || '?'}:${alert.source_port || '?'} → ${alert.dest_ip || '?'}:${alert.dest_port || '?'}`;
  }

  // Update bubble style
  const severity = alert.severity || 'info';
  speechBubble.className = `speech-bubble compact ${severity}`;
  
  // Trigger video avatar talking animation
  playSuriTalking(severity);
}

// Play SURI video when talking
function playSuriTalking(severity) {
  if (!elements.suriAvatar || !elements.avatarVideo) return;
  
  clearTimeout(dialogueTimeout);
  
  // Add talking class for visual effect
  elements.suriAvatar.classList.add('talking');
  
  // Play video from talking section
  if (elements.avatarVideo) {
    elements.avatarVideo.currentTime = 2.0;
    elements.avatarVideo.play();
    elements.avatarVideo.playbackRate = 1.0;
    
    const loopSection = () => {
      if (elements.avatarVideo.currentTime >= 6.0) {
        elements.avatarVideo.currentTime = 2.0;
      }
    };
    elements.avatarVideo.ontimeupdate = loopSection;
  }
  
  // Stop after delay
  dialogueTimeout = setTimeout(() => {
    if (elements.suriAvatar) {
      elements.suriAvatar.classList.remove('talking');
    }
    if (elements.avatarVideo) {
      elements.avatarVideo.ontimeupdate = null;
      elements.avatarVideo.pause();
      elements.avatarVideo.currentTime = 0;
    }
  }, 5000);
}

// Reiniciar métricas
async function resetMetrics() {
  try {
    await fetch('/api/reset', { method: 'POST' });
    showNotification('>> SYSTEM RESET COMPLETE');
  } catch (error) {
    showNotification('>> ERROR: RESET FAILED');
  }
}

// Notificación
function showNotification(message) {
  const toast = document.createElement('div');
  toast.className = 'toast info';
  toast.innerHTML = `<span class="toast-message">${message}</span>`;
  elements.toastContainer.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// Utilidades
function updateTime() {
  elements.currentTime.textContent = new Date().toLocaleTimeString('es-ES');
}

function animateValue(element, start, end, duration) {
  if (start === end) return;

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
  return text.length > length ? text.substring(0, length) + '...' : text;
}
