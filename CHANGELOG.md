# Changelog

All notable changes to the API-Sentinel project will be documented in this file.

## [v1.2.0] - 2026-11-19

### 🎨 Complete Dashboard Redesign (Reference Coverage Theme)
- **Excel-Style Security Validation Coverage Layout**:
  - Implemented the vibrant cyan frame (`#0fb2d9`) enclosing an inner light canvas (`#f1f5f6`) with rounded corners and elevated soft shadows.
  - Narrow left sidebar with active indicator (orange accent bar `#f5a623`) and navigation items: Home, Endpoints, Alerts, Blocked, Users, Reports, Setup.
  - Teal (`#1cc8ae`) and Cyan (`#0eb3d8`) primary series with Orange (`#f5a623`) warning/secondary accents.
  - Re-architected `dashboard/src/App.jsx` from a 1,600-line monolith into modular components: `Sidebar`, `Header`, `Toasts`, `GlobalSearch`, `OverviewPage`, `EndpointsPage`, `AlertsPage`, `BlockedPage`, `UsersPage`, `ReportsPage`, `SetupPage`.
  - Zero-dependency, pure SVG responsive data visualization components (bar charts, dual-line time series, multi-series donuts, combo charts, stacked bars, and gradient area fills) with hover tooltips and interactive click-to-filter capabilities.

### 🌟 New Features & Enhancements
1. **Light / Dark Theme System**:
   - Default light mode matching the reference design.
   - Dark mode toggle with persistent selection saved in `localStorage`.
2. **Date Range Filtering**:
   - Header controls for 5m, 15m, 1h, and All time intervals.
3. **Live Polling Control**:
   - Configurable refresh interval (1s, 2s, 5s, 10s) with pause/resume toggle, persisted in `localStorage`.
4. **Alert Workflow State Machine**:
   - Mark alerts as `New`, `Acknowledged`, `Resolved`, or `False positive`.
   - Persisted in `localStorage` with status chips and filtering.
5. **Threat Profiling (Users Page)**:
   - User risk ranking by alert count and blocked count with SVG mini sparklines.
   - Click-through navigation to filter alerts by user.
6. **Endpoint Detail Slide-Over Drawer**:
   - Inspect endpoint classifications, hit counts, OWASP mappings, and a 1-click "Copy as cURL" button.
7. **Global Search Modal (Ctrl+K / `/`)**:
   - Instant search across endpoints, alerts, users, and object IDs with keyboard navigation (`↑`/`↓`/`Enter`).
8. **Responsive & Print-Ready Layout**:
   - Adaptive sidebar and multi-column grid collapsing on smaller screens.
   - Print stylesheet (`window.print()`) that automatically hides navigation chrome and optimizes content for reports.
9. **Accessibility & Empty States**:
   - Full keyboard focus rings, ARIA labels, semantic roles, skip links, and skeleton loading states.

