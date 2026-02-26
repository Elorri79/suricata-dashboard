// Suricata Dashboard - Main Application v3.0.0

const socket = io();

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
  threatLevel: document.getElementById('threat-level-text'),
  alertsPerMin: document.getElementById('alerts-per-min'),
  threatFill: document.getElementById('threat-fill'),
  threatValue: document.getElementById('threat-value'),
  systemPulse: document.getElementById('system-pulse'),
  matrixBg: document.getElementById('matrix-bg'),
  soundToggle: document.getElementById('sound-toggle'),
  themeToggle: document.getElementById('theme-toggle'),
  fullscreenToggle: document.getElementById('fullscreen-toggle'),
  alertSoundCritical: document.getElementById('alert-sound-critical'),
  alertSoundHigh: document.getElementById('alert-sound-high')
};

const state = {
  soundEnabled: localStorage.getItem('soundEnabled') !== 'false',
  theme: localStorage.getItem('theme') || 'dark',
  isFullscreen: false,
  filters: { severity: '', protocol: '', source_ip: '', dest_ip: '', from: '', to: '' },
  filtersActive: false,
  currentFilterAlerts: []
};

let alertTimestamps = [];
let severityChart, protocolChart, timelineChart, geoMap, geoMarkers = [];
let ipCache = {};
let allAlerts = [];

const IP_API_URL = 'http://ip-api.com/batch';

const IP_FALLBACK = {
  '8.8.8.8': { lat: 37.4223, lon: -122.0848, country: 'United States', city: 'Mountain View' },
  '8.8.4.4': { lat: 37.4223, lon: -122.0848, country: 'United States', city: 'Mountain View' },
  '1.1.1.1': { lat: 34.0522, lon: -118.2437, country: 'United States', city: 'Los Angeles' },
  '1.0.0.1': { lat: 34.0522, lon: -118.2437, country: 'United States', city: 'Los Angeles' },
  '208.67.222.222': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '208.67.220.220': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '9.9.9.9': { lat: 40.7128, lon: -74.0060, country: 'United States', city: 'New York' },
  '149.112.112.112': { lat: 40.7128, lon: -74.0060, country: 'United States', city: 'New York' },
  '64.6.64.6': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '104.16.248.249': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '104.16.249.249': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '172.217.14.206': { lat: 37.4223, lon: -122.0848, country: 'United States', city: 'Mountain View' },
  '142.250.80.46': { lat: 37.4223, lon: -122.0848, country: 'United States', city: 'Mountain View' },
  '23.21.134.22': { lat: 38.8951, lon: -77.0369, country: 'United States', city: 'Washington' },
  '52.84.223.108': { lat: 39.0438, lon: -77.4874, country: 'United States', city: 'Ashburn' },
  '13.107.42.14': { lat: 47.6062, lon: -122.3321, country: 'United States', city: 'Seattle' },
  '204.79.197.200': { lat: 47.6062, lon: -122.3321, country: 'United States', city: 'Seattle' },
  '151.101.1.140': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '151.101.65.140': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '185.199.108.153': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' },
  '140.82.112.4': { lat: 37.7749, lon: -122.4194, country: 'United States', city: 'San Francisco' }
};

async function lookupIPs(ipList) {
  const uncached = ipList.filter(ip => !ipCache[ip] && !IP_FALLBACK[ip]);
  if (uncached.length === 0) return;
  
  try {
    const response = await fetch(IP_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(uncached.map(ip => ({ query: ip, fields: 'query,country,regionName,city,lat,lon' })))
    });
    
    if (!response.ok) throw new Error('API error');
    
    const results = await response.json();
    results.forEach(r => {
      if (r.status === 'success') {
        ipCache[r.query] = { lat: r.lat, lon: r.lon, country: r.country, city: r.city };
      }
    });
  } catch (e) {
    console.warn('GeoIP lookup failed, using fallback:', e);
  }
}

function init() {
  applyTheme(state.theme);
  updateSoundIcon();
  initMatrix();
  initCharts();
  initGeoMap();
  initEventListeners();
  initSuriAvatar();
  updateTime();
  setInterval(updateTime, 1000);
  setInterval(updateAPS, 1000);
  connectSocket();
  
  setInterval(() => {
    fetch('/api/metrics')
      .then(res => res.json())
      .then(data => updateDashboard(data))
      .catch(err => console.error('Polling error:', err));
  }, 10000);
  
  setTimeout(() => {
    document.querySelectorAll('.skeleton').forEach(el => el.classList.remove('skeleton'));
    document.querySelectorAll('.skeleton-item, .skeleton-row').forEach(el => el.remove());
  }, 500);
}

const VIDEO_IDLE_START = 1.2;
const VIDEO_IDLE_END = 2.0;
const VIDEO_TALK_START = 2.0;
const VIDEO_TALK_END = 6.0;

const videoState = { mode: 'idle', loopHandler: null, currentVideo: null };

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
  if (videoState.loopHandler) {
    video.removeEventListener('timeupdate', videoState.loopHandler);
    videoState.loopHandler = null;
  }
  if (video.currentTime < startTime || video.currentTime >= endTime) {
    video.currentTime = startTime;
  }
  const handler = () => {
    if (video.currentTime >= endTime) video.currentTime = startTime;
  };
  videoState.loopHandler = handler;
  video.addEventListener('timeupdate', handler);
  video.play().catch(() => {});
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
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  setInterval(draw, 50);
  window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  });
}

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
  if (percent >= 75) { level = 'CRITICAL'; className = 'critical'; }
  else if (percent >= 50) { level = 'HIGH'; className = 'high'; }
  else if (percent >= 25) { level = 'MEDIUM'; className = 'medium'; }
  else { level = 'LOW'; className = ''; }
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
  } else {
    elements.systemPulse?.classList.remove('alert');
  }
}

const chartColors = {
  critical: '#ff0044', high: '#ff6600', medium: '#ffee00', low: '#00ff88', info: '#8800ff',
  tcp: '#00f0ff', udp: '#ff00ff', icmp: '#00ff88', http: '#ff6600', https: '#ffee00', dns: '#ff0044', timeline: '#00f0ff'
};

function initCharts() {
  Chart.defaults.color = '#6a8fa8';
  Chart.defaults.font.family = 'JetBrains Mono';

  const severityCtx = document.getElementById('severity-chart')?.getContext('2d');
  if (severityCtx) {
    severityChart = new Chart(severityCtx, {
      type: 'doughnut',
      data: {
        labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
        datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: [chartColors.critical + 'cc', chartColors.high + 'cc', chartColors.medium + 'cc', chartColors.low + 'cc', chartColors.info + 'cc'], borderColor: [chartColors.critical, chartColors.high, chartColors.medium, chartColors.low, chartColors.info], borderWidth: 2, hoverOffset: 10 }]
      },
      options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom', labels: { color: '#6a8fa8', padding: 10, usePointStyle: true, pointStyle: 'rectRounded', font: { family: 'JetBrains Mono', size: 10 } } }, tooltip: { backgroundColor: '#0a0f14', borderColor: '#00f0ff', borderWidth: 1, titleColor: '#00f0ff', bodyColor: '#e0f0ff', padding: 10 } } }
    });
  }

  const protocolCtx = document.getElementById('protocol-chart')?.getContext('2d');
  if (protocolCtx) {
    protocolChart = new Chart(protocolCtx, {
      type: 'doughnut',
      data: {
        labels: ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'],
        datasets: [{ data: [0, 0, 0, 0, 0, 0], backgroundColor: [chartColors.tcp + 'cc', chartColors.udp + 'cc', chartColors.icmp + 'cc', chartColors.http + 'cc', chartColors.https + 'cc', chartColors.dns + 'cc'], borderColor: [chartColors.tcp, chartColors.udp, chartColors.icmp, chartColors.http, chartColors.https, chartColors.dns], borderWidth: 2, hoverOffset: 10 }]
      },
      options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom', labels: { color: '#6a8fa8', padding: 10, usePointStyle: true, pointStyle: 'rectRounded', font: { family: 'JetBrains Mono', size: 10 } } }, tooltip: { backgroundColor: '#0a0f14', borderColor: '#00f0ff', borderWidth: 1, titleColor: '#00f0ff', bodyColor: '#e0f0ff', padding: 10 } } }
    });
  }

  const timelineCtx = document.getElementById('timeline-chart')?.getContext('2d');
  if (timelineCtx) {
    timelineChart = new Chart(timelineCtx, {
      type: 'line',
      data: { labels: [], datasets: [{ label: 'ALERTS/HOUR', data: [], borderColor: chartColors.timeline, backgroundColor: (ctx) => { const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, ctx.chart.height); g.addColorStop(0, 'rgba(0, 240, 255, 0.3)'); g.addColorStop(1, 'rgba(0, 240, 255, 0.0)'); return g; }, borderWidth: 2, fill: true, tension: 0.4, pointRadius: 3, pointHoverRadius: 7, pointBackgroundColor: chartColors.timeline, pointBorderColor: '#030508', pointBorderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, interaction: { intersect: false, mode: 'index' }, scales: { x: { grid: { color: 'rgba(0, 240, 255, 0.07)', drawBorder: false }, ticks: { color: '#6a8fa8', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 12 } }, y: { beginAtZero: true, grid: { color: 'rgba(0, 240, 255, 0.07)', drawBorder: false }, ticks: { color: '#6a8fa8', font: { family: 'JetBrains Mono', size: 10 } } } }, plugins: { legend: { display: false }, tooltip: { backgroundColor: '#0a0f14', borderColor: '#00f0ff', borderWidth: 1, titleColor: '#00f0ff', bodyColor: '#e0f0ff', padding: 10 } } }
    });
  }
}

function initGeoMap() {
  const mapContainer = document.getElementById('geo-map');
  if (!mapContainer) return;
  
  try {
    geoMap = L.map('geo-map', {
      center: [30, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: false,
      minZoom: 2,
      maxZoom: 6,
      worldCopyJump: false,
      crs: L.CRS.EPSG3857,
      maxBounds: [[-85, -180], [85, 180]],
      maxBoundsViscosity: 1.0
    });
    
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
      maxZoom: 19,
      minZoom: 2,
      noWrap: true,
      bounds: [[-85, -180], [85, 180]],
      reuseTiles: true,
      errorTileUrl: '',
      subdomains: 'abc'
    }).addTo(geoMap);

    geoMap.on('moveend', () => {
      const bounds = geoMap.getBounds();
      const validBounds = L.latLngBounds([[-85, -180], [85, 180]]);
      if (!validBounds.contains(bounds.getNorthWest()) || !validBounds.contains(bounds.getSouthEast())) {
        geoMap.setView([30, 0], 2);
      }
    });
    
    setTimeout(() => geoMap.invalidateSize(), 100);
  } catch (e) {
    console.warn('GeoMap init failed:', e);
  }
}

async function updateGeoMap(alerts) {
  if (!geoMap) return;
  
  geoMarkers.forEach(m => geoMap.removeLayer(m));
  geoMarkers = [];
  
  const uniqueIPs = [];
  const ipLocations = {};
  
  alerts.forEach(alert => {
    if (alert.source_ip && !alert.source_ip.startsWith('192.168.') && !alert.source_ip.startsWith('10.') && !alert.source_ip.startsWith('172.')) {
      const ip = alert.source_ip;
      if (!ipLocations[ip]) {
        ipLocations[ip] = { count: 0, severity: alert.severity };
        uniqueIPs.push(ip);
      }
      ipLocations[ip].count++;
      if (alert.severity === 'critical') ipLocations[ip].severity = 'critical';
      else if (alert.severity === 'high' && ipLocations[ip].severity !== 'critical') ipLocations[ip].severity = 'high';
    }
  });
  
  if (uniqueIPs.length > 0) {
    await lookupIPs(uniqueIPs);
  }
  
  const colors = { critical: '#ff0044', high: '#ff6600', medium: '#ffee00', low: '#00ff88', info: '#8800ff' };
  
  Object.entries(ipLocations).forEach(([ip, data]) => {
    const geo = ipCache[ip] || IP_FALLBACK[ip];
    if (!geo) {
      console.log('No geo for IP:', ip);
      return;
    }
    
    const color = colors[data.severity] || colors.info;
    const size = Math.min(10 + data.count * 2, 40);
    
    const popupContent = `
      <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #1a2632;">
        <strong style="color: #0088aa;">${ip}</strong><br/>
        <span style="color: #4a5a6a;">${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}</span><br/>
        <span style="color: #4a5a6a;">Alerts: ${data.count}</span><br/>
        <span style="color: ${color}; font-weight: bold;">${data.severity.toUpperCase()}</span>
      </div>
    `;
    
    const marker = L.circleMarker([geo.lat, geo.lon], {
      radius: size / 2,
      fillColor: color,
      color: color,
      weight: 1,
      opacity: 0.8,
      fillOpacity: 0.6
    }).addTo(geoMap);
    
    marker.bindPopup(popupContent, {
      closeButton: true,
      closeOnClick: false,
      autoClose: false,
      className: 'custom-popup'
    });
    geoMarkers.push(marker);
  });
  
  const geoCount = document.getElementById('geo-count');
  if (geoCount) geoCount.textContent = `${Object.keys(ipLocations).length} sources`;
}

function initEventListeners() {
  elements.alertSearch?.addEventListener('input', filterAlerts);
  
  document.getElementById('reset-btn')?.addEventListener('click', resetMetrics);
  document.getElementById('apply-filters')?.addEventListener('click', applyFilters);
  document.getElementById('clear-filters')?.addEventListener('click', clearFilters);
  document.getElementById('export-csv')?.addEventListener('click', () => exportAlerts('csv'));
  document.getElementById('export-json')?.addEventListener('click', () => exportAlerts('json'));
  
  elements.soundToggle?.addEventListener('click', toggleSound);
  elements.themeToggle?.addEventListener('click', toggleTheme);
  elements.fullscreenToggle?.addEventListener('click', toggleFullscreen);
  
  document.getElementById('filter-severity')?.addEventListener('change', (e) => state.filters.severity = e.target.value);
  document.getElementById('filter-protocol')?.addEventListener('change', (e) => state.filters.protocol = e.target.value);
  document.getElementById('filter-source-ip')?.addEventListener('input', (e) => state.filters.source_ip = e.target.value);
  document.getElementById('filter-dest-ip')?.addEventListener('input', (e) => state.filters.dest_ip = e.target.value);
  document.getElementById('filter-from')?.addEventListener('change', (e) => state.filters.from = e.target.value);
  document.getElementById('filter-to')?.addEventListener('change', (e) => state.filters.to = e.target.value);
}

function toggleSound() {
  state.soundEnabled = !state.soundEnabled;
  localStorage.setItem('soundEnabled', state.soundEnabled);
  updateSoundIcon();
}

function updateSoundIcon() {
  const waves = document.getElementById('sound-waves');
  if (waves) waves.style.display = state.soundEnabled ? 'block' : 'none';
}

function playAlertSound(severity) {
  if (!state.soundEnabled) return;
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);
    
    if (severity === 'critical') {
      oscillator.frequency.value = 880;
      oscillator.type = 'square';
      gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.5);
    } else {
      oscillator.frequency.value = 440;
      oscillator.type = 'sine';
      gainNode.gain.setValueAtTime(0.2, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
    }
    
    oscillator.start(audioCtx.currentTime);
    oscillator.stop(audioCtx.currentTime + 0.5);
  } catch (e) {}
}

function toggleTheme() {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', state.theme);
  applyTheme(state.theme);
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  if (theme === 'light') {
    document.body.classList.add('light-theme');
  } else {
    document.body.classList.remove('light-theme');
  }
}

function toggleFullscreen() {
  if (!document.fullscreenElement) {
    document.documentElement.requestFullscreen();
    state.isFullscreen = true;
  } else {
    document.exitFullscreen();
    state.isFullscreen = false;
  }
}

function connectSocket() {
  socket.on('connect', () => {
    if (elements.connectionStatus) {
      elements.connectionStatus.textContent = 'ONLINE';
      elements.connectionStatus.style.color = '#00ff88';
      elements.connectionStatus.parentElement?.querySelector('.pulse')?.style.setProperty('background', '#00ff88');
    }
  });

  socket.on('disconnect', () => {
    if (elements.connectionStatus) {
      elements.connectionStatus.textContent = 'OFFLINE';
      elements.connectionStatus.style.color = '#ff0044';
      elements.connectionStatus.parentElement?.querySelector('.pulse')?.style.setProperty('background', '#ff0044');
    }
  });

  socket.on('metrics', (data) => updateDashboard(data));
  socket.on('newAlert', (alert) => handleNewAlert(alert));
}

function updateDashboard(data) {
  if (!data) return;
  
  animateValue(elements.totalAlerts, parseInt(elements.totalAlerts?.textContent?.replace(/\./g, '')?.replace(/,/g, '') || 0), data.totalAlerts || 0, 400);
  animateValue(elements.criticalCount, parseInt(elements.criticalCount?.textContent?.replace(/\./g, '')?.replace(/,/g, '') || 0), data.alertsBySeverity?.critical || 0, 400);
  animateValue(elements.highCount, parseInt(elements.highCount?.textContent?.replace(/\./g, '')?.replace(/,/g, '') || 0), data.alertsBySeverity?.high || 0, 400);
  animateValue(elements.mediumCount, parseInt(elements.mediumCount?.textContent?.replace(/\./g, '')?.replace(/,/g, '') || 0), data.alertsBySeverity?.medium || 0, 400);
  animateValue(elements.lowCount, parseInt(elements.lowCount?.textContent?.replace(/\./g, '')?.replace(/,/g, '') || 0), data.alertsBySeverity?.low || 0, 400);
  animateValue(elements.infoCount, parseInt(elements.infoCount?.textContent?.replace(/\./g, '')?.replace(/,/g, '') || 0), data.alertsBySeverity?.info || 0, 400);

  updateThreatLevel(data);
  updateSeverityChart(data.alertsBySeverity);
  updateProtocolChart(data.alertsByProtocol);
  updateTimelineChart(data.alertsTimeline);
  updateSignatureList(data.topSignatures);
  updateIPList(elements.sourceIPList, data.topSourceIPs);
  updateIPList(elements.destIPList, data.topDestIPs);

  if (data.recentAlerts && allAlerts.length === 0 && !state.filtersActive) {
    allAlerts = data.recentAlerts;
    updateGeoMap(allAlerts);
  }

  if (data.recentAlerts && data.recentAlerts.length > 0) {
    updateSpeechBubble(data.recentAlerts[0]);
  }

  if (!state.filtersActive && !elements.alertSearch?.value) {
    updateAlertsTable(state.filtersActive ? state.currentFilterAlerts.slice(0, 50) : (data.recentAlerts || []));
  }
}

function handleNewAlert(alert) {
  const now = Date.now();
  alertTimestamps.push(now);
  alertTimestamps = alertTimestamps.filter(t => now - t <= 60000);

  if (!state.filtersActive) {
    allAlerts.unshift(alert);
    if (allAlerts.length > 200) allAlerts.pop();
  }

  playSuriTalking(alert.severity);
  playAlertSound(alert.severity);

  if (alert.severity === 'critical' || alert.severity === 'high') {
    showToast(alert);
  }

  if (!state.filtersActive && !elements.alertSearch?.value) {
    updateAlertsTable(state.filtersActive ? state.currentFilterAlerts.slice(0, 50) : allAlerts.slice(0, 50));
  }

  updateGeoMap(state.filtersActive ? state.currentFilterAlerts : allAlerts).then(() => {
    // Map updated
  });

  fetch('/api/metrics')
    .then(res => res.json())
    .then(data => updateDashboard(data))
    .catch(err => console.error('Error fetching metrics:', err));
}

function updateAPS() {
  const now = Date.now();
  const last10s = alertTimestamps.filter(t => now - t <= 10000);
  const aps = (last10s.length / 10).toFixed(1);
  if (elements.apsValue) {
    elements.apsValue.textContent = aps;
    elements.apsValue.classList.toggle('high-aps', parseFloat(aps) > 1);
  }
  const last60s = alertTimestamps.filter(t => now - t <= 60000);
  if (elements.alertsPerMin) {
    elements.alertsPerMin.textContent = last60s.length;
  }
}

function updateSeverityChart(severityData) {
  if (!severityChart) return;
  severityChart.data.datasets[0].data = [
    severityData?.critical || 0, severityData?.high || 0, severityData?.medium || 0,
    severityData?.low || 0, severityData?.info || 0
  ];
  severityChart.update();
}

function updateProtocolChart(protocolData) {
  if (!protocolChart) return;
  protocolChart.data.datasets[0].data = [
    protocolData?.TCP || 0, protocolData?.UDP || 0, protocolData?.ICMP || 0,
    protocolData?.HTTP || 0, protocolData?.HTTPS || 0, protocolData?.DNS || 0
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

function updateSignatureList(signatures) {
  if (!elements.signatureList) return;
  if (!signatures || signatures.length === 0) {
    elements.signatureList.innerHTML = '<li class="empty-state">WAITING FOR DATA...</li>';
    return;
  }
  const maxCount = signatures[0]?.count || 1;
  elements.signatureList.innerHTML = signatures.map((sig, i) => {
    const pct = Math.round((sig.count / maxCount) * 100);
    const rank = i + 1;
    return `<li><div class="sig-rank">${rank < 10 ? '0' + rank : rank}</div><div class="sig-info"><span class="signature-name" title="${escapeHtml(sig.signature)}">${escapeHtml(sig.signature)}</span><div class="sig-bar-wrap"><div class="sig-bar" style="width:${pct}%"></div></div></div><span class="signature-count">${sig.count.toLocaleString('es-ES')}</span></li>`;
  }).join('');
}

function updateIPList(container, ips) {
  if (!container) return;
  if (!ips || ips.length === 0) {
    container.innerHTML = '<li class="empty-state">WAITING FOR DATA...</li>';
    return;
  }
  const maxCount = ips[0]?.count || 1;
  container.innerHTML = ips.map((ip, i) => {
    const pct = Math.round((ip.count / maxCount) * 100);
    return `<li><div class="sig-rank">${(i + 1).toString().padStart(2, '0')}</div><div class="sig-info"><span class="signature-name">${ip.ip}</span><div class="sig-bar-wrap"><div class="sig-bar ip-bar" style="width:${pct}%"></div></div></div><span class="ip-count">${ip.count.toLocaleString('es-ES')}</span></li>`;
  }).join('');
}

function updateAlertsTable(alerts) {
  if (!elements.alertsTableBody) return;
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

function filterAlerts() {
  const query = elements.alertSearch?.value?.toLowerCase()?.trim() || '';
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

function applyFilters() {
  const params = new URLSearchParams();
  if (state.filters.severity) params.append('severity', state.filters.severity);
  if (state.filters.protocol) params.append('protocol', state.filters.protocol);
  if (state.filters.source_ip) params.append('source_ip', state.filters.source_ip);
  if (state.filters.dest_ip) params.append('dest_ip', state.filters.dest_ip);
  if (state.filters.from) params.append('from', state.filters.from);
  if (state.filters.to) params.append('to', state.filters.to);
  params.append('limit', '100');
  
  fetch(`/api/alerts?${params}`)
    .then(res => res.json())
    .then(alerts => {
      state.filtersActive = true;
      state.currentFilterAlerts = alerts;
      updateAlertsTable(alerts.slice(0, 50));
      updateGeoMap(alerts);
    })
    .catch(err => console.error('Filter error:', err));
}

function clearFilters() {
  state.filters = { severity: '', protocol: '', source_ip: '', dest_ip: '', from: '', to: '' };
  state.filtersActive = false;
  state.currentFilterAlerts = [];
  document.getElementById('filter-severity').value = '';
  document.getElementById('filter-protocol').value = '';
  document.getElementById('filter-source-ip').value = '';
  document.getElementById('filter-dest-ip').value = '';
  document.getElementById('filter-from').value = '';
  document.getElementById('filter-to').value = '';
  fetch('/api/metrics').then(res => res.json()).then(data => { allAlerts = data.recentAlerts || []; updateAlertsTable(allAlerts.slice(0, 50)); updateGeoMap(allAlerts); });
}

function exportAlerts(format) {
  window.open(`/api/alerts/export?format=${format}`, '_blank');
}

function showToast(alert) {
  if (!elements.toastContainer) return;
  const existingToasts = elements.toastContainer.querySelectorAll('.toast');
  if (existingToasts.length >= 4) existingToasts[0].remove();

  const toast = document.createElement('div');
  toast.className = `toast ${alert.severity || 'info'}`;
  toast.innerHTML = `
    <div class="toast-icon">${alert.severity === 'critical' ? '!' : 'i'}</div>
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
  updateAndroidStatus(alert.severity);
  updateSpeechBubble(alert);
  setTimeout(() => { toast.classList.add('fadeout'); setTimeout(() => toast.remove(), 400); }, 6000);
}

const faceMessages = {
  critical: '! CRITICAL THREAT DETECTED', high: '! HIGH SEVERITY ALERT',
  medium: '> ANALYZING ANOMALY', low: '> SCANNING ACTIVITY', info: '> MONITORING NETWORK'
};

let androidTimeout, dialogueTimeout;

function updateAndroidStatus(severity) {
  const statusText = elements.androidStatusText;
  const statusDot = document.getElementById('android-status-dot');
  if (!statusText) return;

  const colorMap = { critical: chartColors.critical, high: chartColors.high, medium: chartColors.medium, low: chartColors.low, info: chartColors.timeline };
  const dotClassMap = { critical: 'status-dot-mini alert', high: 'status-dot-mini warning', medium: 'status-dot-mini', low: 'status-dot-mini safe', info: 'status-dot-mini' };

  statusText.textContent = faceMessages[severity] || faceMessages.info;
  statusText.style.color = colorMap[severity] || colorMap.info;
  if (statusDot) statusDot.className = dotClassMap[severity] || dotClassMap.info;

  clearTimeout(androidTimeout);
  androidTimeout = setTimeout(() => {
    if (statusText) { statusText.textContent = 'SURI ONLINE'; statusText.style.color = chartColors.timeline; }
    if (statusDot) statusDot.className = 'status-dot-mini safe';
  }, 6000);
}

function updateSpeechBubble(alert) {
  const speechBubble = document.querySelector('.speech-bubble');
  if (!speechBubble || !alert) return;
  const speechText = document.getElementById('speech-text');
  const speechMeta = document.getElementById('speech-meta');
  if (speechText) speechText.textContent = truncate(alert.signature || 'UNKNOWN SIGNATURE', 60);
  if (speechMeta) speechMeta.textContent = `${alert.source_ip || '?'}:${alert.source_port || '?'} → ${alert.dest_ip || '?'}:${alert.dest_port || '?'} [${alert.protocol || '-'}]`;
  speechBubble.className = `speech-bubble compact ${alert.severity || 'info'}`;
}

function setAvatarSeverity(severity) {
  if (!elements.suriAvatar) return;
  elements.suriAvatar.classList.remove('sev-idle', 'sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info');
  elements.suriAvatar.classList.add(`sev-${severity}`);
}

function playSuriTalking(severity) {
  if (!elements.suriAvatar) return;
  setAvatarSeverity(severity || 'idle');
  changeVideo(severity || 'info');
  const video = elements.avatarVideo;
  if (video) {
    video.onloadeddata = () => { video.currentTime = VIDEO_TALK_START; setVideoTalking(); video.onloadeddata = null; };
    video.load();
  }
  clearTimeout(dialogueTimeout);
  dialogueTimeout = setTimeout(() => {
    changeVideo('info');
    const video = elements.avatarVideo;
    if (video) { video.onloadeddata = () => { setVideoIdle(); video.onloadeddata = null; }; video.load(); }
    setTimeout(() => setAvatarSeverity('idle'), 1000);
  }, 6000);
}

function initSuriAvatar() {
  const speechText = document.getElementById('speech-text');
  const speechMeta = document.getElementById('speech-meta');
  if (speechText) speechText.textContent = 'System ready. All sensors online.';
  if (speechMeta) speechMeta.textContent = 'Awaiting threat data';
  setAvatarSeverity('idle');

  const video = elements.avatarVideo;
  if (!video) return;
  video.muted = true;
  video.loop = false;
  video.playsInline = true;
  videoState.currentVideo = '/videos/ok.mp4';

  video.addEventListener('loadedmetadata', () => { video.currentTime = VIDEO_IDLE_START; setVideoIdle(true); });
  video.addEventListener('canplay', () => { if (videoState.mode === 'idle' && video.paused) setVideoLoop(VIDEO_IDLE_START, VIDEO_IDLE_END); }, { once: true });

  const resumeOnInteraction = () => { if (video.paused) video.play().catch(() => {}); document.removeEventListener('click', resumeOnInteraction); document.removeEventListener('keydown', resumeOnInteraction); };
  document.addEventListener('click', resumeOnInteraction);
  document.addEventListener('keydown', resumeOnInteraction);

  video.addEventListener('error', () => {
    console.warn('Avatar video failed to load, showing placeholder');
    if (elements.suriAvatar) {
      elements.suriAvatar.innerHTML = `<div class="avatar-fallback"><svg viewBox="0 0 100 120" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="faceGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1a2a3a"/><stop offset="100%" stop-color="#050a0f"/></linearGradient></defs><ellipse cx="50" cy="65" rx="38" ry="46" fill="url(#faceGrad)" stroke="#00e5ff" stroke-width="1.5" opacity="0.9"/><ellipse cx="36" cy="62" rx="9" ry="11" fill="#00e5ff" opacity="0.9"><animate attributeName="ry" values="11;1;11" dur="4s" keyTimes="0;0.48;0.5" repeatCount="indefinite"/></ellipse><ellipse cx="64" cy="62" rx="9" ry="11" fill="#00e5ff" opacity="0.9"><animate attributeName="ry" values="11;1;11" dur="4s" keyTimes="0;0.48;0.5" repeatCount="indefinite"/></ellipse><line x1="38" y1="92" x2="62" y2="92" stroke="#00e5ff" stroke-width="3" stroke-linecap="round" opacity="0.8"/></svg><div class="avatar-fallback-scan"></div></div>`;
    }
  });

  if (video.readyState >= 2) { video.currentTime = VIDEO_IDLE_START; setVideoIdle(true); }

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
    document.addEventListener('mouseleave', () => { avatarFrame.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg)'; });
  }
}

async function resetMetrics() {
  try {
    await fetch('/api/reset', { method: 'POST' });
    allAlerts = [];
    alertTimestamps = [];
    showNotification('>> SYSTEM RESET COMPLETE');
    updateAlertsTable([]);
    updateGeoMap([]);
  } catch (error) {
    showNotification('>> ERROR: RESET FAILED');
  }
}

function showNotification(message) {
  if (!elements.toastContainer) return;
  const toast = document.createElement('div');
  toast.className = 'toast info';
  toast.innerHTML = `<div class="toast-icon">i</div><div class="toast-body"><div class="toast-signature">${message}</div></div>`;
  elements.toastContainer.appendChild(toast);
  setTimeout(() => { toast.classList.add('fadeout'); setTimeout(() => toast.remove(), 400); }, 3000);
}

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
    if (progress < 1) { requestAnimationFrame(update); }
    else { element.textContent = formatNumber(end); element.classList.add('updated'); setTimeout(() => element.classList.remove('updated'), 300); }
  }
  requestAnimationFrame(update);
}

function easeOutQuad(t) { return t * (2 - t); }
function formatNumber(num) { return num.toLocaleString('es-ES'); }
function formatTimestamp(timestamp) {
  if (!timestamp) return '--:--:--';
  return new Date(timestamp).toLocaleString('es-ES').replace(',', '');
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

document.addEventListener('DOMContentLoaded', () => {
  init();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
});
