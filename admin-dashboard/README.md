# 🛡️ FraudShield AI — Admin Operations Console

[![React](https://img.shields.io/badge/React-18.2-61dafb?style=flat-square&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-5.1-646CFF?style=flat-square&logo=vite)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC?style=flat-square&logo=tailwind-css)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](../LICENSE)

Enterprise Security Operations Center (SOC) web application for real-time threat monitoring, campaign correlation, digital forensics, IOC management, and enrolled device telemetry.

---

## 🏗️ Architecture & Component Overview

`	ext
admin-dashboard/
├── dist/                   # Production-optimized SPA build artifacts
├── src/
│   ├── components/         # Reusable UI components & layouts
│   │   ├── ErrorBoundary.tsx # Graceful React crash-containment boundary
│   │   ├── Layout.tsx      # Responsive sidebar navigation & topbar status
│   │   └── ...             # Modals, risk gauges, badges, and stat cards
│   ├── pages/              # Dedicated SOC Operational Views
│   │   ├── Overview.tsx               # Executive threat posture & live event stream
│   │   ├── ThreatDetectionCenter.tsx  # Manual URL scanner & SHAP XAI breakdown
│   │   ├── CampaignMonitor.tsx        # Cross-device phishing campaign correlation
│   │   ├── DangerousDownloads.tsx     # Double-extension & malicious file interception
│   │   ├── FileAnalysisCenter.tsx     # Zero-execution static document forensics
│   │   ├── ThreatBlocklist.tsx        # Active IOC rules & incremental sync manager
│   │   ├── AdminAlerts.tsx            # Alert triage, severity filters & notifications
│   │   ├── AttackInvestigation.tsx    # In-depth forensic dossier & indicator pivot
│   │   ├── DevicesMonitor.tsx         # Enrolled extension heartbeats & client inventory
│   │   └── Settings.tsx               # Engine weights, API keys & circuit breaker status
│   ├── services/           # Backend API integration & WebSocket client
│   │   ├── api.ts          # Axios/Fetch client with auth headers & error handling
│   │   └── websocket.ts    # Resilient WebSocket connection with auto-reconnect
│   ├── types/              # TypeScript interface definitions (Scan, Threat, Event)
│   ├── App.tsx             # Route management & global state providers
│   ├── index.css           # Tailwind base, components, and utilities
│   └── main.tsx            # React 18 DOM mount with strict mode
├── Dockerfile              # Multi-stage Docker build with Nginx SPA routing
├── index.html              # HTML entrypoint with secure Content Security Policy
├── package.json            # Node.js dependencies and build scripts
├── postcss.config.js       # PostCSS configuration for Tailwind
├── tailwind.config.js      # SOC dark-mode theme color palette & font definitions
├── tsconfig.json           # Strict TypeScript compiler options
└── vite.config.ts          # Vite build and development server configuration
`

---

## 🌟 Key SOC Capabilities

| Module | Operational Capability | Key Metrics / Features |
| :--- | :--- | :--- |
| **Executive Overview** | Bird\'s-eye view of enterprise cyber threat posture. | Live threat velocity, active campaigns, fleet health, severity distribution. |
| **Detection Center** | On-demand URL scanning & deep signal decomposition. | Hybrid risk score (0-100), SHAP feature attribution bar chart, domain age. |
| **Campaign Monitor** | Graph & cluster analysis of distributed phishing attacks. | Infrastructure reuse, targeted brands, affected device clusters. |
| **File Forensics** | Safe zero-execution document inspection. | Metadata parsing, embedded URLs/IPs, SHA-256 hashing, PDF/Office sanitization. |
| **Dangerous Downloads** | Real-time monitoring of intercepted browser downloads. | Double-extension (.pdf.exe) traps, MIME spoofing detection. |
| **IOC Blocklist** | Global and tenant-specific threat indicator management. | Real-time revocation, bulk CSV export, source intelligence tagging. |
| **Fleet Monitoring** | Browser extension fleet telemetry and status. | Client version tracking, active heartbeats, offline status alerts. |
| **System Settings** | Tunable heuristic weights & operational thresholds. | Circuit breaker status, external threat intelligence API configurations. |

---

## 🚀 Getting Started

### Prerequisites
- **Node.js**: v18.x or v20.x+
- **npm**: v9.x or v10.x+
- Running **FraudShield AI Backend** at http://localhost:8000

### 1. Installation
`ash
cd admin-dashboard
npm install
`

### 2. Development Mode
Run the Vite development server with hot module replacement (HMR):
`ash
npm run dev
`
The console will be accessible at: **[http://localhost:5173](http://localhost:5173)**

### 3. Production Build
Type-check TypeScript source and bundle minified assets:
`ash
npm run build
`
Build output is generated in dist/.

### 4. Preview Production Build
`ash
npm run preview
`

---

## 🐳 Docker Deployment

The dashboard includes a multi-stage production Dockerfile:
1. **Stage 1 (Build)**: Compiles TypeScript and builds minified assets using Node.js Alpine.
2. **Stage 2 (Runtime)**: High-performance Nginx Alpine web server configured with SPA rewrite routing.

`ash
# Build Docker image
docker build -t fraudshield-admin-dashboard .

# Run container on port 80
docker run -p 80:80 fraudshield-admin-dashboard
`

When using docker-compose.yml from the root directory, the admin dashboard is automatically built, networked with the backend, and exposed on port 5173.

---

## 🔒 Security Best Practices

- **Zero Inline Scripts**: Clean Content Security Policy (CSP) compatible architecture.
- **XSS Containment**: React standard JSX text sanitization prevents DOM injection.
- **Formula Injection Mitigation**: All CSV exports sanitize leading formula triggers (=, +, -, @).
- **Resilient Error Boundaries**: Unhandled component exceptions are caught and contained without crashing the entire SOC dashboard.
