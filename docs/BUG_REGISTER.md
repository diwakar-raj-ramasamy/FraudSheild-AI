# 🐛 FraudShield AI — Comprehensive Bug Register

**Document Version**: 2.0.0  
**Last Updated**: November 14, 2026  
**Auditor / Maintainer**: Principal Software Architect & QA Automation Lead  

---

## Bug Summary Index

| Bug ID | Severity | Component | Summary | Status |
|---|---|---|---|---|
| **BUG-2026-001** | High | Browser Extension | Service Worker import error `Cannot use import statement outside a module` | **RESOLVED** |
| **BUG-2026-002** | Medium | Browser Extension | Manifest V3 icon format incompatibility (SVG icons in Chrome toolbar) | **RESOLVED** |
| **BUG-2026-003** | High | Dashboard / Backend | Overview dashboard displayed synthetic baseline counts when DB was empty | **RESOLVED** |
| **BUG-2026-004** | High | Scoring Engine | Scoring engine accumulated uncalibrated scalar points instead of documented ratio | **RESOLVED** |
| **BUG-2026-005** | High | Scoring Engine | `AttributeError: 'NoneType' object has no attribute 'upper'` under load | **RESOLVED** |
| **BUG-2026-006** | Medium | Core Config | Insecure default `SECRET_KEY` accepted in production mode | **RESOLVED** |
| **BUG-2026-007** | High | Database / Tests | Relative SQLite database resolution redirected isolated test databases to production DB | **RESOLVED** |
| **BUG-2026-008** | Medium | Admin Security Tests | Test campaign and blocklist records committed to DB without teardown cleanup | **RESOLVED** |
| **BUG-2026-009** | Medium | Load Benchmark | Async load runner polluted production SQLite database during benchmark executions | **RESOLVED** |
| **BUG-2026-010** | Low | Build Systems | PostCSS typeless package.json warning during Vite bundle compilation | **RESOLVED** |
| **BUG-2026-011** | Medium | Repository Config | `docs/` folder excluded from version control by `.gitignore` | **RESOLVED** |

---

## Detailed Bug Reports

### BUG-2026-001: Manifest V3 Service Worker Import Error
- **Date Discovered**: November 14, 2026
- **Severity**: High
- **Component**: `browser-extension` (`manifest.json`, `dist/service-worker.js`)
- **Symptoms**: Chrome extension failed to register service worker. Console displayed: `service-worker.js:1 (anonymous function)`: `SyntaxError: Cannot use import statement outside a module`.
- **Root Cause**: The compiled background service worker utilized ES module imports/exports, but `manifest.json` declared `"background": { "service_worker": "service-worker.js" }` without `"type": "module"`.
- **Reproduction**: Load unpacked `browser-extension/dist` in Google Chrome `chrome://extensions`.
- **Resolution**: Added `"type": "module"` to `background` configuration in `manifest.json` and ensured Rollup bundles all service worker dependencies into a self-contained module.

---

### BUG-2026-002: Manifest V3 Extension Icon Format Rejection
- **Date Discovered**: November 14, 2026
- **Severity**: Medium
- **Component**: `browser-extension` (`manifest.json`, `icons/`)
- **Symptoms**: Extension toolbar icon showed a generic puzzle piece or blank letter in Chrome.
- **Root Cause**: `manifest.json` referenced `.svg` vector files (`icons/icon-16.svg`), which are not supported for Chrome action icons in Manifest V3.
- **Reproduction**: Inspect extension details page in Chrome. Warning: "Could not load icon 'icons/icon-16.svg'".
- **Resolution**: Generated valid, multi-resolution PNG icons (16x16, 48x48, 128x128) with proper IHDR chunks and alpha transparency, updating all manifest references to PNG.

---

### BUG-2026-003: Synthetic Baseline Data Displayed in Admin Dashboard
- **Date Discovered**: November 14, 2026
- **Severity**: High
- **Component**: `backend/app/api/metrics.py`, `admin-dashboard/src/pages/Overview.tsx`
- **Symptoms**: When the SQLite database had 0 scans and 0 threats, the SOC Overview console displayed 24 scans, 8 threats, and synthetic mock charts.
- **Root Cause**: Backend endpoint `get_security_overview` used `max(total_scans, 24)` and hardcoded synthetic velocity arrays. Frontend `Overview.tsx` had a fallback mock state object.
- **Reproduction**: Purge all rows from `fraudshield.db` and open `http://localhost:5173`.
- **Resolution**: Removed all artificial `max()` wrappers and synthetic velocity fallbacks. Implemented authentic SQL timestamp aggregation querying real tables. Default state set to 0.

---

### BUG-2026-004: Scoring Engine Mathematical Formula Deviation
- **Date Discovered**: November 14, 2026
- **Severity**: High
- **Component**: `backend/app/engines/scoring_engine.py`
- **Symptoms**: Scores did not match the documented hybrid risk formula: $\text{Final Score} = \min(100, 0.45 \cdot S_{\text{heuristic}} + 0.35 \cdot S_{\text{ML}} + 0.20 \cdot S_{\text{intel}})$.
- **Root Cause**: `ScoringEngine` accumulated raw points directly into an uncalibrated scalar sum rather than weighting normalized sub-engine component vectors.
- **Reproduction**: Scan a URL with known ML probability and heuristic markers; observe calculated total did not obey component ratios.
- **Resolution**: Refactored `ScoringEngine.calculate()` to compute normalized components:
  - $S_{\text{heuristic}} \in [0, 100]$
  - $S_{\text{ML}} \in [0, 100]$
  - $S_{\text{intel}} \in [0, 100]$
  Applied exact $45/35/20$ mathematical ratio and added deterministic hard overrides ($\ge 95$) for verified blocklist or threat intel hits.

---

### BUG-2026-005: AttributeError on Null Brand Spoofed Field Under Load
- **Date Discovered**: November 14, 2026
- **Severity**: High
- **Component**: `backend/app/engines/scoring_engine.py` (Line 122)
- **Symptoms**: `POST /api/scan/url` intermittently returned HTTP 500 during stress testing with: `AttributeError: 'NoneType' object has no attribute 'upper'`.
- **Root Cause**: When `fake_login_analysis` had `"brand_spoofed": None`, the expression `fake_login_analysis.get('brand_spoofed', 'monitored brand')` returned `None` because dictionary key existed with value `None`. Subsequent `.upper()` call crashed.
- **Reproduction**: Submit scan payload triggering credential form on a typosquatted domain where `brand_spoofed` evaluates to `None`.
- **Resolution**: Replaced with null-coalescing fallback:
  `target_brand = fake_login_analysis.get("brand_spoofed") or typo_analysis.get("spoofed_brand") or "monitored brand"`
  `override_reason = f"Credential form impersonating {str(target_brand).upper()}"`

---

### BUG-2026-006: Insecure Production Secret Key Allowed
- **Date Discovered**: November 14, 2026
- **Severity**: Medium
- **Component**: `backend/app/core/config.py`
- **Symptoms**: System permitted booting in production mode with default or low-entropy `SECRET_KEY`.
- **Root Cause**: `Settings` lacked validation preventing default strings when `ENVIRONMENT=production`.
- **Reproduction**: Run with `ENVIRONMENT=production` and default secret key.
- **Resolution**: Added `@field_validator("SECRET_KEY")` raising a fatal `ValueError` if key is under 32 characters or matches known insecure defaults in production.

---

### BUG-2026-007: SQLite Path Resolver Collapsing Custom Databases
- **Date Discovered**: November 14, 2026
- **Severity**: High
- **Component**: `backend/app/core/config.py` (`resolve_sqlite_path`)
- **Symptoms**: Setting `DATABASE_URL=sqlite:///./test_runner.db` was forcibly rewritten to `sqlite:///.../fraudshield.db`, causing test suites to pollute the production database.
- **Root Cause**: Validator checked `if v.startswith("sqlite:///./"):` and unconditionally returned path ending in `fraudshield.db` regardless of filename.
- **Reproduction**: Set `DATABASE_URL=sqlite:///./custom.db` and inspect `settings.DATABASE_URL`.
- **Resolution**: Extracted relative filename dynamically:
  `rel_file = v[len("sqlite:///./"):]`
  `db_path = os.path.join(base_dir, rel_file).replace("\\", "/")`

---

### BUG-2026-008: Admin Security Tests Polluting Production Database
- **Date Discovered**: November 14, 2026
- **Severity**: Medium
- **Component**: `security/tests/test_admin_security.py`
- **Symptoms**: Running pytest left persistent test records (`FraudCampaign` and `BlocklistEntry` for `phish-bank-auth-2026.net`) in the database.
- **Root Cause**: Tests inserted objects directly into the database session without post-test deletion in a `finally` block.
- **Reproduction**: Run pytest and query `SELECT COUNT(*) FROM fraud_campaigns`.
- **Resolution**: Wrapped assertions in `try ... finally` blocks guaranteeing automatic deletion of created records.

---

### BUG-2026-009: Async Load Runner Polluting Production Database
- **Date Discovered**: November 14, 2026
- **Severity**: Medium
- **Component**: `backend/load_tests/async_load_runner.py`
- **Symptoms**: Executing load benchmarks created 16 scan results, 14 detection events, and 3 campaigns in production `fraudshield.db`.
- **Root Cause**: Load runner connected to default database without overriding `DATABASE_URL`.
- **Reproduction**: Run `python backend/load_tests/async_load_runner.py` and inspect database.
- **Resolution**: Configured runner to automatically isolate workloads to `test_load_fraudshield.db` with table initialization on startup and file deletion on completion.

---

### BUG-2026-010: Typeless Package.json Warnings in Frontend Builds
- **Date Discovered**: November 14, 2026
- **Severity**: Low
- **Component**: `browser-extension/package.json`, `admin-dashboard/package.json`
- **Symptoms**: Node.js emitted `MODULE_TYPELESS_PACKAGE_JSON` warning during Vite builds.
- **Root Cause**: Missing `"type": "module"` in `package.json` while using ES module configuration in `postcss.config.js`.
- **Reproduction**: Run `npm run build` in either frontend folder.
- **Resolution**: Added `"type": "module"` to both `package.json` files.

---

### BUG-2026-011: Documentation Folder Excluded From Version Control
- **Date Discovered**: November 14, 2026
- **Severity**: Medium
- **Component**: `.gitignore`
- **Symptoms**: Critical architecture, audit, and update logs in `docs/` were ignored by git.
- **Root Cause**: `.gitignore` contained `docs/` and `documents/` entries.
- **Reproduction**: Run `git status` after editing files in `docs/`.
- **Resolution**: Removed `docs/` and `documents/` exclusions from `.gitignore`.

