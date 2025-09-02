# 🛠️ Web Vulnerability Scanner – **2025 Feature Roadmap**

Transform your `web-vuln-scanner` into a powerful, enterprise-ready security toolkit.

##  PHASE 1: Core Stability & Coverage

| Feature | Description | Module / File |
|---------|-------------|---------------|
|  Modular Scanners | One scanner per vulnerability (modular logic) | `lib/scanners/*.js` |
|  Report Generator | Support `HTML`, `JSON`, and `Markdown` output | `lib/reporters/*.js` |
|  Version Detection | Check outdated software versions | `version-check.js` |
|  Smart CLI Flags | Add `--quick`, `--deep`, `--risk-insight`, `--show-evidence` | `bin/cli.js` |
|  Dependency Scanner | Audit JS libraries like `npm audit` or `retire.js` | `lib/scanners/dependency.js` |

##  PHASE 2: AI & Dev Experience

| Feature | Description | Status |
|---------|-------------|--------|
|  Gemini AI Fixes | One-click AI fix recommendation per vulnerability |  Done |
|  Fix Playground | Live testing for code patch simulation |  Integrated |
|  LLM Explain Button | Ask "What is this vuln?", "Fix it", "Example exploit" | In Progress |
|  React Dashboard | Web-based UI with real-time report + graphing | `/frontend` |

##  PHASE 3: Deep Web Coverage

| Feature | Description | File / Module |
|---------|-------------|---------------|
| 🧬 Puppeteer Crawler | Crawl dynamic JS apps (React, Angular, Vue) | `lib/crawler-puppeteer.js` |
|  Auth Scanning | Scan login-only areas using form/cookie/JWT | `lib/auth.js` |
|  Session Recorder | Record login headers for reuse with `--use-session` | `lib/session-recorder.js` |
|  Script Scanner | Check all 3rd-party `<script src="">` for threats | `lib/scanners/external-scripts.js` |

##  PHASE 4: Enterprise Integrations

| Feature | Description | Notes / Location |
|---------|-------------|------------------|
|  GitHub Actions Support | Prebuilt `web-vuln-scanner.yml` CI template | `examples/github-actions.yml` |
|  OWASP Report Mode | Output mapped to OWASP Top 10 | `lib/reporters/owasp.js` |
|  PCI / GDPR Templates | Templates for compliance audit | `templates/*.json` |
|  CI/CD Integrations | Jenkins, GitHub, CircleCI pipelines | `ci/*` |
|  Frontend Auth (JWT) | Login-protected frontend for team accounts | Future SaaS |
|  Jira / Slack Alerts | Send high-risk findings to issue tracker or Slack | `lib/integrations/*.js` |

##  Ideal Folder Structure

```
web-vuln-scanner/
├── bin/
│   └── cli.js                # CLI entrypoint
├── lib/
│   ├── index.js              # Exports scanner
│   ├── scanner.js            # Core scanner
│   ├── crawler.js            # HTML-based crawler
│   ├── crawler-puppeteer.js  # JS-based crawler
│   ├── auth.js               # Login scanning
│   ├── session-recorder.js   # Session manager
│   ├── version-check.js
│   ├── scanners/
│   │   ├── xss.js
│   │   ├── sql-injection.js
│   │   ├── ssl-tls.js
│   │   ├── external-scripts.js
│   │   └── dependency.js
│   ├── reporters/
│   │   ├── html-reporter.js
│   │   ├── markdown-reporter.js
│   │   ├── json-reporter.js
│   │   └── owasp.js
│   └── integrations/
│       ├── jira.js
│       └── slack.js
├── frontend/                 # React + Tailwind UI
│   ├── public/
│   └── src/
├── examples/
│   └── github-actions.yml
├── docs/
│   └── architecture.md
├── tests/
│   └── scanner.test.js
├── package.json
└── .github/
    └── workflows/
        └── publish.yml
```

##  Suggested Next Priorities

1.  Add `--risk-insight` and `--show-evidence` (done)
2.  Add Puppeteer + Auth (done)
3.  External script scanning (done)
4.  Finalize Gemini AI suggestion flow
5.  Add OWASP + PCI report templates
6.  Add CI examples (GitHub, Jenkins)
7.  Launch frontend dashboard (Phase 2)