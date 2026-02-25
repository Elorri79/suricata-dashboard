# AGENTS.md - Suricata Dashboard

## Project Overview
Real-time cyberpunk-styled web dashboard for monitoring Suricata IDS/IPS alerts. Built with Node.js, Express, Socket.IO, and vanilla JavaScript frontend.

## Project Structure
```
suricata-dashboard/
├── server.js              # Main Express server (backend)
├── public/
│   ├── index.html        # Dashboard HTML
│   ├── css/style.css    # Cyberpunk styling
│   ├── js/app.js        # Frontend application logic
│   └── js/chart.min.js # Chart.js library
├── logs/                 # Default log directory
├── package.json
└── README.md
```

## Build/Lint/Test Commands

### Running the Application
```bash
npm install       # Install dependencies
npm start        # Start server (alias: npm run dev)
```
Server runs on http://localhost:3000 (configurable via PORT env var)

### Environment Variables
```bash
export PORT=3000              # Server port (default: 3000)
export SURICATA_LOG=/path/to/eve.json  # Suricata log file
```

### Testing Endpoints (with server running)
```bash
# Start injecting random alerts every 2 seconds
curl http://localhost:3000/api/test/start

# Stop test injection
curl http://localhost:3000/api/test/stop

# Inject specific severity alert
curl http://localhost:3000/api/test/critical
curl http://localhost:3000/api/test/high
curl http://localhost:3000/api/test/medium

# Reset all metrics
curl -X POST http://localhost:3000/api/reset
```

### Single Test Approach
There is no formal test framework in this project. To test functionality:
1. Start server: `npm start`
2. Use curl commands above to inject test data
3. Check http://localhost:3000 for visual verification

### Adding Tests
If adding tests, use a simple approach:
```bash
# Install test runner
npm install --save-dev jest

# Run single test
npx jest --testPathPattern=filename.test.js
```

## Code Style Guidelines

### General Principles
- Keep code simple and readable
- No comments unless explaining complex logic
- 2-space indentation (matching existing code)

### JavaScript Version
- Backend: **CommonJS** (`require()` syntax) - see server.js
- Frontend: **ES6+** (`const`, `let`, arrow functions) - see public/js/app.js

### Imports
```javascript
// Backend (CommonJS)
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');

// Frontend (ES6 via CDN/Script tags in HTML)
<script src="/socket.io/socket.io.js"></script>
<script src="/js/chart.min.js"></script>
```

### Naming Conventions
- **Variables/Functions**: camelCase (`totalAlerts`, `processAlert`)
- **Constants**: UPPER_SNAKE_CASE (`PORT`, `MAX_APS_SAMPLES`)
- **Files**: kebab-case (`server.js`, `app.js`)
- **DOM Elements**: camelCase prefixed with meaningful name

### Types
- No TypeScript - plain JavaScript only
- Use explicit types in JSDoc comments if needed for documentation
- Handle undefined/null gracefully with fallback values

### Error Handling
- Use try/catch for synchronous JSON parsing and file operations
- Log errors with descriptive messages using `console.error()`
- Return appropriate HTTP status codes in API routes
```javascript
// Example error handling pattern
try {
  const data = JSON.parse(line);
  // process data
} catch (error) {
  // Ignore malformed lines (common in log files)
}
```

### API Design
- RESTful endpoints under `/api/` prefix
- Return JSON responses
- Use proper HTTP methods (GET for retrieval, POST for mutations)
```javascript
app.get('/api/metrics', (req, res) => {
  res.json({ /* data */ });
});

app.post('/api/reset', (req, res) => {
  res.json({ success: true });
});
```

### WebSocket Events
- Use Socket.IO for real-time communication
- Emit events: `metrics`, `newAlert`
- Handle connection/disconnection events

### Frontend Patterns
- Store DOM references in an `elements` object at module top
- Use event listeners for user interactions
- Prefer `const` over `let` - use `let` only for values that change
- Use optional chaining (`?.`) for safe property access

### CSS/Styling
- Custom cyberpunk aesthetic (see public/css/style.css)
- Use CSS custom properties for colors
- Keep styles in the dedicated CSS file

### File Operations
- Use synchronous file operations for simplicity (`readFileSync`, `statSync`)
- Use streaming/buffering for large log files
- Handle file rotation (truncation detection)

### Security
- No sensitive data in code (use environment variables)
- Validate input on API endpoints
- CORS configured for Socket.IO: `{ origin: "*", methods: ["GET", "POST"] }`

### Git Practices
- Create feature branches for changes
- Write descriptive commit messages
- Test locally before committing

## Technology Stack
- **Runtime**: Node.js 18+
- **Backend**: Express.js 4.18.2, Socket.IO 4.7.2
- **Frontend**: Vanilla JavaScript, Chart.js
- **Styling**: Custom CSS (cyberpunk theme)

## Key Files to Know
- `server.js:1-435` - Main server with API routes, WebSocket handling, log file polling
- `public/js/app.js:1-1016` - Frontend with Socket.IO client, Chart.js charts, DOM manipulation
- `public/index.html` - Dashboard HTML structure
- `public/css/style.css` - Cyberpunk visual styling
