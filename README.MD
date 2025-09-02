# 🔍 Web Vulnerability Scanner CLI

A powerful and pluggable **JavaScript CLI tool** to scan websites for common security vulnerabilities:

-  SQL Injection  
-  XSS (Cross-Site Scripting)  
-  CSRF  
-  CSP Misconfigurations  
-  SSL/TLS Issues  
-  Insecure HTTP Headers  
-  Directory Traversal  
-  Open Ports  
-  Outdated JavaScript Libraries  
-  IDOR  
-  RCE Checks

Generate reports in **Console**, **JSON**, **HTML**, or **Markdown** formats.

---

##  Installation

```bash
git clone https://github.com/pratikacharya1234/Web-Vulnerability-Scanner.git
cd Web-Vulnerability-Scanner
npm install
```

>  Requires **Node.js v18+**

---

##  Key Dependencies

| Package         | Role                            |
|----------------|----------------------------------|
| commander     | CLI interface                   |
| chalk         | Colored console output          |
| ora           | CLI loading spinners            |
| node-fetch    | Makes HTTP requests             |
| jsdom         | Parses HTML into DOM            |
| cheerio       | Lightweight HTML traversal      |
| debug         | Debug logger                    |
| p-limit       | Controls concurrency            |
| open          | Opens HTML reports in browser   |

---

##  How to Use

### Basic Usage

```bash
node bin/cli.js https://example.com
```

###  Advanced Scan

```bash
node bin/cli.js https://juice-shop.herokuapp.com \
  --only xss,sql,headers \
  --format html \
  --output report.html \
  --open \
  --verbose
```

---

###  Available CLI Options

| Option               | Description                                            |
|----------------------|--------------------------------------------------------|
| --output           | Save results to file (.json, .html, .md)         |
| --format           | Output format: console, html, json, markdown   |
| --only             | Run only selected modules (e.g., xss,sql)            |
| --headers          | Custom headers as JSON                                 |
| --cookies          | Cookies to attach to request                           |
| --depth            | Max crawl depth (default: 1)                           |
| --disable-crawler  | Scan only the main URL                                 |
| --verbose          | Show detailed vulnerability breakdown                  |
| --open             | Automatically open HTML report in browser              |
| --risk-insight     | Include detailed risk analysis in reports              |
| --show-evidence    | Display vulnerable code snippets in output             |

---

##  Programmatic API Usage

### Install as a Dependency

```bash
npm install web-vuln-scanner
```

###  Terminal Scan Example

```js
const scanner = require('web-vuln-scanner');

(async () => {
  const results = await scanner.scan('https://example.com', {
    scanModules: ['xss', 'headers', 'ssl'],
    timeout: 30000,
    verbose: true,
    depth: 1,
    concurrency: 5,
    userAgent: 'MyScanner/1.0'
  });

  console.log(JSON.stringify(results, null, 2));
})();
```

###  Browser Report Example

```js
const fs = require('fs');
const path = require('path');
const scanner = require('web-vuln-scanner');
const { generateReport } = require('web-vuln-scanner/lib/reporters/html-reporter');
const open = (...args) => import('open').then(m => m.default(...args));

(async () => {
  const url = 'https://example.com';
  const results = await scanner.scan(url, {
    scanModules: ['xss', 'headers', 'ssl'],
    timeout: 30000,
    depth: 1,
    concurrency: 5
  });

  const report = {
    target: url,
    summary: results.summary,
    vulnerabilities: results.vulnerabilities
  };

  const filePath = path.resolve(__dirname, 'scan-report.html');
  fs.writeFileSync(filePath, generateReport(report));
  console.log(` Report saved at: ${filePath}`);
  await open(filePath);
})();
```

###  Sample Output

```json
{
  "summary": {
    "total": 5,
    "high": 1,
    "medium": 2,
    "low": 2,
    "info": 0
  },
  "vulnerabilities": [
    {
      "type": "xss",
      "severity": "high",
      "description": "Potential reflected XSS found",
      "recommendation": "Sanitize user input.",
      "evidence": "<script>alert(1)</script>",
      "url": "https://example.com"
    }
  ]
}
```

---

##  Project Structure

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
```

---

##  2025 Feature Roadmap

We're building a powerful, enterprise-ready security toolkit. See our [roadmap.md](https://github.com/pratikacharya1234/Web-Vulnerability-Scanner/blob/main/ROADMAP.md) for the detailed plan:

### Current Progress:
-  Modular scanners implementation
-  Report generators (HTML, JSON, Markdown)
-  Smart CLI flags (risk-insight, show-evidence)
-  Puppeteer crawler for JS apps
-  Gemini AI fix recommendations

### Coming Soon:
-  LLM vulnerability explainer
-  Web-based dashboard UI
-  Authentication scanning
-  OWASP & compliance reporting
-  Jira & Slack integrations

---

##  Contributing

We welcome your help!  
Please check out [CONTRIBUTING.md](https://github.com/pratikacharya1234/Web-Vulnerability-Scanner/blob/main/CONTRIBUTING.md) for how to submit a PR and see our [roadmap.md](https://github.com/pratikacharya1234/Web-Vulnerability-Scanner/blob/main/ROADMAP.md) for upcoming features.

---

##  License

MIT © 2025  
Made  by [Pratik Acharya](https://github.com/pratikacharya1234)