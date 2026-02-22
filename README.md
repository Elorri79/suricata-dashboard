# Suricata Dashboard - AI Monitor Edition

A real-time cyberpunk-styled web dashboard for monitoring and visualizing Suricata IDS/IPS alerts with an interactive AI co-pilot named SURI.

![Dashboard Overview](screenshot1.png)

## Overview

Suricata Dashboard is a lightweight Node.js application that provides real-time visualization of Suricata intrusion detection/prevention system events. It features a stunning cyberpunk aesthetic inspired by Metal Hurlant, with a unique AI co-pilot (SURI) that reacts to threats in real-time.

## Features

- **AI Co-Pilot SURI**: Interactive video avatar that reacts to threats with different status messages based on severity level
- **Real-time Metrics**: Live updates via WebSocket connections
- **Alert Visualizations**:
  - Alerts by severity level (Critical, High, Medium, Low, Info)
  - Alerts by protocol (TCP, UDP, ICMP, HTTP, DNS, HTTPS)
  - 24-hour activity timeline
- **Top Statistics**:
  - Most triggered detection signatures
  - Top source IPs (attackers)
  - Top destination IPs (targets)
- **Threat Radar**: Visual radar display showing threat activity
- **Alert Browser**: Recent alerts table with search functionality
- **Toast Notifications**: Desktop notifications for new critical alerts
- **RESTful API**: Programmatic access to metrics and alerts
- **Responsive Design**: Adapts to any screen size

## Quick Start

```bash
# Clone and install
git clone https://github.com/Elorri79/suricata-dashboard.git
cd suricata-dashboard
npm install

# Run
npm start
```

Then open **http://localhost:3000** in your browser.

## Requirements

- Node.js 18+
- npm or yarn
- Suricata IDS/IPS (optional - includes test data generator)

## Configuration

### Environment Variables (Optional)

```bash
export SURICATA_LOG=/path/to/eve.json  # Default: logs/eve.json
export PORT=3000                        # Default: 3000
```

## Running the Application

### Start the server:

```bash
npm start
```

The dashboard will be available at: **http://localhost:3000**

The application includes a built-in test data generator that creates realistic alert data, so you can see the dashboard in action immediately without configuring Suricata.

## What's New - SURI AI Monitor

The latest version features **SURI**, an interactive AI co-pilot:

- **Video Avatar**: A cyborg character that serves as your AI monitor
- **Real-time Reactions**: SURI changes status based on detected threats
- **Speech Bubble**: Shows the latest threat signature and source/destination IPs
- **Alert History**: Displays attack patterns and threat intelligence

### SURI Status Messages:

| Status | Meaning |
|--------|---------|
| !! DANGER !! | Critical severity alert |
| !! WARNING !! | High severity alert |
| > ANALYZING | Medium severity alert |
| > SCANNING | Low severity alert |
| > MONITORING | Info severity / Normal |
| SURI ONLINE | System operational |

## REST API

The application exposes a RESTful API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/metrics` | GET | Get current metrics and statistics |
| `/api/alerts` | GET | Get recent alerts (supports `?limit=50`) |
| `/api/reset` | POST | Reset all metrics to zero |

### Example:

```bash
curl http://localhost:3000/api/metrics
```

## Integration with Suricata

To connect with a real Suricata installation:

1. Configure Suricata to output EVE JSON logs in `suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
```

2. Set the environment variable:

```bash
export SURICATA_LOG=/var/log/suricata/eve.json
npm start
```

## Technology Stack

- **Backend**: Node.js, Express.js
- **Real-time**: Socket.IO (WebSocket)
- **Frontend**: Vanilla JavaScript, Chart.js
- **Styling**: Custom CSS (Cyberpunk/Metal Hurlant aesthetic)

## Project Structure

```
suricata-dashboard/
├── server.js              # Main server application
├── public/
│   ├── index.html         # Main dashboard UI
│   ├── css/
│   │   └── style.css     # Cyberpunk dashboard styles
│   ├── js/
│   │   ├── app.js        # Frontend application logic
│   │   └── chart.min.js  # Chart.js library
│   └── videos/
│       └── avatar.mp4    # SURI AI avatar video
├── logs/                 # Default log directory
├── package.json
└── README.md
```

## Screenshots

### Dashboard Overview
![Dashboard Overview](screenshot1.png)

### Alert Details & SURI Reactions
![Alert Details](screenshot2.png)

## Credits

This project was developed using:
- **OpenCode** - AI-powered development assistant
- **SURI Avatar** - Custom video content

## License

MIT
