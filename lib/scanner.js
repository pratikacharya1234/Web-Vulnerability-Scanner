const fetch = require('node-fetch');
const { JSDOM } = require('jsdom');
const debug = require('debug')('web-vuln-scanner');
const pLimit = require('p-limit');
const { Crawler } = require('./crawler');

// Import scanners
const headerScanner = require('./scanners/header');
const xssScanner = require('./scanners/xss');
const sqlScanner = require('./scanners/sql-injection');
const sslScanner = require('./scanners/ssl-tls');
const portScanner = require('./scanners/port');
const dirTraversalScanner = require('./scanners/dir-traversal');
const csrfScanner = require('./scanners/csrf');
const cspScanner = require('./scanners/csp');
const versionScanner = require('./scanners/version-check');
const rceScanner = require('./scanners/rce');
const idorScanner = require('./scanners/idor');
const misconfigScanner = require('./scanners/misconfigured-headers');

class Scanner {
  constructor(url, options = {}) {
    this.url = this.normalizeUrl(url);
    this.options = {
      timeout: 15000,
      userAgent: 'WebVulnScanner/1.0',
      scanModules: [
        'headers', 'xss', 'sql', 'ssl', 'ports',
        'dirTraversal', 'csrf', 'csp', 'versionCheck',
        'rce', 'idor', 'misconfiguredHeaders'
      ],
      depth: 2,
      concurrency: 5,
      disableCrawler: false,
      headers: {},
      ...options
    };
    this.results = {
      url: this.url,
      timestamp: new Date().toISOString(),
      scannedUrls: [],
      summary: { total: 0, high: 0, medium: 0, low: 0, info: 0 },
      vulnerabilities: []
    };
    this.crawler = new Crawler({
      baseUrl: this.url,
      depth: this.options.depth,
      concurrency: this.options.concurrency,
      userAgent: this.options.userAgent,
      headers: this.options.headers
    });
  }

  normalizeUrl(url) {
    return url.startsWith('http') ? url : `https://${url}`;
  }

  async fetchPage(url, method = 'GET', data = null) {
    try {
      debug(`Fetching ${url}`);
      const options = {
        method,
        headers: {
          'User-Agent': this.options.userAgent,
          ...this.options.headers
        },
        timeout: this.options.timeout,
        redirect: 'follow'
      };

      if (data && method !== 'GET') {
        options.body = typeof data === 'string' ? data : JSON.stringify(data);
        options.headers['Content-Type'] = typeof data === 'string' ? 'application/x-www-form-urlencoded' : 'application/json';
      }

      const response = await fetch(url, options);
      const contentType = response.headers.get('content-type') || '';
      const content = await response.text();
      let dom = null;

      if (contentType.includes('text/html')) {
        try { dom = new JSDOM(content); } catch (e) { debug(`DOM parse failed: ${e.message}`); }
      }

      return {
        status: response.status,
        headers: Object.fromEntries(response.headers),
        content,
        dom,
        url: response.url
      };
    } catch (error) {
      debug(`Failed to fetch ${url}: ${error.message}`);
      throw new Error(`Fetch error: ${error.message}`);
    }
  }

  async runScan() {
    debug(`Starting scan: ${this.url}`);
    const limit = pLimit(this.options.concurrency);
    let pages = [this.url];

    if (!this.options.disableCrawler) {
      const crawled = await this.crawler.crawl();
      pages = [...new Set([this.url, ...crawled])];
    }

    this.results.scannedUrls = pages;
    const scanTasks = pages.map(url => limit(() => this.scanOneUrl(url)));
    await Promise.all(scanTasks);

    if (this.options.scanModules.includes('ssl')) {
      const sslResults = await sslScanner.scan(this.url);
      this.addResults(sslResults);
    }

    if (this.options.scanModules.includes('ports')) {
      const portResults = await portScanner.scan(this.url);
      this.addResults(portResults);
    }

    return this.results;
  }

  async scanOneUrl(url) {
    try {
      const page = await this.fetchPage(url);
      await this.scanUrl(page, url);
    } catch (err) {
      debug(`Error on ${url}: ${err.message}`);
      this.results.vulnerabilities.push({
        type: 'scan_error',
        url,
        severity: 'info',
        description: `Scan error: ${err.message}`
      });
    }
  }

  async scanUrl(page, url) {
    const scanners = {
      headers: headerScanner,
      xss: xssScanner,
      sql: sqlScanner,
      dirTraversal: dirTraversalScanner,
      csrf: csrfScanner,
      csp: cspScanner,
      versionCheck: versionScanner,
      rce: rceScanner,
      idor: idorScanner,
      misconfiguredHeaders: misconfigScanner
    };

    const modulesToRun = this.options.scanModules.filter(name => scanners[name]);
    const results = await Promise.all(modulesToRun.map(name => scanners[name].scan(page, url)));

    results.forEach(moduleResults => {
      moduleResults.forEach(result => {
        if (!result.url) result.url = url;
        this.addResults([result]);
      });
    });
  }

  addResults(vulns) {
    this.results.vulnerabilities.push(...vulns);
    vulns.forEach(v => {
      this.results.summary.total++;
      if (v.severity && this.results.summary[v.severity] !== undefined) {
        this.results.summary[v.severity]++;
      }
    });
  }
}

module.exports = Scanner;
