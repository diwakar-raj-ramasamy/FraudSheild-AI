# 🛡️ FraudShield AI — Chrome Browser Extension

[![Chrome Extension](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-orange?style=flat-square&logo=googlechrome)](manifest.json)
[![React](https://img.shields.io/badge/React-18.2-61dafb?style=flat-square&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-5.1-646CFF?style=flat-square&logo=vite)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC?style=flat-square&logo=tailwind-css)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](../LICENSE)

Client-side browser endpoint protection providing zero-latency offline threat blocking, real-time URL heuristic inspection, DOM credential-harvesting detection, dangerous download interception, and explainable Safe Exit protection.

---

## 🏗️ Architecture & Component Overview

`	ext
browser-extension/
├── dist/                   # Bundled Manifest V3 extension ready for Chrome loading
│   ├── assets/             # Compiled CSS, JS chunks, and SVG icons
│   ├── manifest.json       # Production Manifest V3 configuration
│   ├── service-worker.js   # Background event router & API orchestrator
│   ├── content-script.js   # Passive DOM signal extractor
│   └── src/                # Warning, Safe-Exit, and Popup HTML entrypoints
├── public/                 # Static extension assets (icons, brand marks)
├── src/
│   ├── background/
│   │   └── service-worker.ts # Manifest V3 worker: webNavigation, downloads & storage
│   ├── content/
│   │   └── content-script.ts # Safe DOM signal analyzer (no keystroke logging)
│   ├── popup/              # Browser toolbar popup interface
│   │   ├── App.tsx         # Real-time URL threat status, risk gauge & settings
│   │   ├── index.html      # Popup HTML wrapper
│   │   └── main.tsx        # React mount for toolbar popup
│   ├── safe-exit/          # Safe Exit isolation page
│   │   ├── SafeExit.tsx    # Session neutralization & emergency tab closure
│   │   └── index.html      # Safe Exit HTML wrapper
│   ├── warning/            # Threat Interception interstitial page
│   │   ├── ThreatWarning.tsx # Explainable threat breakdown & bypass controls
│   │   └── index.html      # Threat warning HTML wrapper
│   ├── services/           # Backend API connector & offline cache manager
│   ├── types/              # Extension messaging & DOM signal TypeScript types
│   ├── utils/              # URL parsing, canonicalization & browser page filters
│   └── index.css           # Tailwind utilities & theme definitions
├── manifest.json           # Development Manifest V3 specification
├── package.json            # Node.js dependencies and compilation commands
├── tsconfig.json           # Strict TypeScript configuration
└── vite.config.ts          # Multi-entrypoint Rollup configuration for MV3
`

---

## 🛡️ Core Defense Capabilities

### 1. Dual-Tier Navigation Filtering
- **Tier 1 (Instant Offline Blocklist)**: Checks visited domains against an in-memory/local storage Bloom filter and IOC table before network requests leave the browser.
- **Tier 2 (Asynchronous Backend Scan)**: Queries the FraudShield AI backend (/api/v1/scan/url) for composite heuristic analysis, ML scoring, and external threat intelligence.

### 2. Privacy-First DOM Signal Analysis
- Content scripts extract non-invasive structural indicators (e.g., presence of password inputs, one-time passcode fields, urgent financial phrasing, hidden iframes).
- **Privacy Guarantee**: Does **not** capture keystrokes, form input values, cookies, or user credentials.

### 3. Intercept & Threat Warning
- When a threat threshold is exceeded (Score $\ge 70$), the background worker intercepts the navigation and renders the warning/index.html interstitial screen.
- Explains the exact threat classification (Phishing, Typosquatting, Fake Login, Financial Scam), lists high-risk indicators, and provides one-click navigation to safety.

### 4. Safe Exit Protection
- Users can trigger Safe Exit (safe-exit/index.html) to immediately terminate connection with a suspicious site, clear temporary tab storage, and safely redirect to a clean browser state.

### 5. Download Monitoring
- Hooks chrome.downloads.onCreated to detect double-extension masquerading (e.g., invoice_2026.pdf.exe) and risky archive payloads before file execution.

---

## 🔒 Permission Justifications (Principle of Least Privilege)

| Permission | Purpose & Technical Necessity |
| :--- | :--- |
| storage | Stores offline threat blocklist rules, user preferences, and cached scan verdicts locally. |
| ctiveTab | Inspects DOM structure on the actively viewed page only when threat analysis is requested. |
| webNavigation | Intercepts navigation attempts before page rendering to block drive-by malware and credential harvesters. |
| downloads | Inspects download metadata (filename, URL, MIME type) to prevent malicious executable drops. |
| larms | Periodically triggers background synchronization of threat blocklist updates every 30 minutes. |

---

## 🚀 Installation & Loading into Google Chrome

### Prerequisites
- Google Chrome (or Chromium-based browser: Brave, Microsoft Edge, Opera) v108+
- Node.js v18+ or v20+
- Running **FraudShield AI Backend** at http://localhost:8000

### Step 1: Install Dependencies & Build
`ash
cd browser-extension
npm install
npm run build
`
This compiles TypeScript files and bundles popup, warning, safe-exit, service worker, and content script into the dist/ directory.

### Step 2: Load into Google Chrome
1. Open Google Chrome and navigate to:
   `	ext
   chrome://extensions/
   `
2. In the top-right corner, toggle **Developer mode** to **ON**.
3. In the top-left menu, click **Load unpacked**.
4. In the file picker, select the rowser-extension/dist folder inside this repository:
   `	ext
   d:\FraudShield AI\browser-extension\dist
   `
5. The **FraudShield AI - Cyber Threat Defense** extension will appear in your installed extensions list.
6. Click the Extensions (puzzle piece) icon in the Chrome toolbar and pin **FraudShield AI** for quick access.

---

## 🛠️ Development & Live Iteration

When modifying extension source code:
`ash
# Rebuild extension bundles
npm run build
`
After rebuilding:
1. Navigate to chrome://extensions/.
2. Locate **FraudShield AI** and click the **Reload** (circular arrow) icon.
3. If modifying content scripts, refresh any open browser tabs to inject the updated script.

---

## 🧪 Verifying Extension Operation

1. **Verify Background Service Worker**:
   - In chrome://extensions/, click **service worker** under FraudShield AI to open DevTools for the background script.
   - Confirm console shows initialization and blocklist synchronization messages.
2. **Test Toolbar Popup**:
   - Click the FraudShield AI icon in the toolbar.
   - Observe current URL safety score, analysis status, and protection toggles.
3. **Simulate Threat Interception**:
   - Open a test URL flagged with phishing heuristics or navigate to chrome-extension://<id>/src/warning/index.html to inspect the warning interface.
