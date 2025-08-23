const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { JSDOM } = require('jsdom');
const debug = require('debug')('web-vuln-scanner');
// Handle both CommonJS and ES module versions of p-limit
let pLimit;
try {
  pLimit = require('p-limit');
} catch (error) {
  // If the above fails, try dynamic import for ES modules
  pLimit = null;
}
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
        options.headers['Content-Type'] = typeof data === 'string'
          ? 'application/x-www-form-urlencoded'
          : 'application/json';
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
      try {
        const crawled = await this.crawler.crawl();
        pages = [...new Set([this.url, ...crawled])];
      } catch (crawlerError) {
        debug(`Crawler error: ${crawlerError.message}`);
        // Continue with just the main URL if crawler fails
      }
    }

    this.results.scannedUrls = pages;
    const scanTasks = pages.map(url => limit(() => this.scanOneUrl(url)));
    
    try {
      await Promise.all(scanTasks);
    } catch (scanError) {
      debug(`Scan tasks error: ${scanError.message}`);
    }

    // Run SSL scan if enabled
    if (this.options.scanModules.includes('ssl')) {
      try {
        const sslResults = await sslScanner.scan(this.url);
        this.addResults(sslResults);
      } catch (sslError) {
        debug(`SSL scan error: ${sslError.message}`);
        this.addResults([{
          type: 'ssl_scan_error',
          url: this.url,
          severity: 'info',
          description: `SSL scan failed: ${sslError.message}`
        }]);
      }
    }

    // Run port scan if enabled
    if (this.options.scanModules.includes('ports')) {
      try {
        const portResults = await portScanner.scan(this.url);
        this.addResults(portResults);
      } catch (portError) {
        debug(`Port scan error: ${portError.message}`);
        this.addResults([{
          type: 'port_scan_error',
          url: this.url,
          severity: 'info',
          description: `Port scan failed: ${portError.message}`
        }]);
      }
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
    
    try {
      const results = await Promise.all(
        modulesToRun.map(async (name) => {
          try {
            const scanResult = await scanners[name].scan(page, url);
            // Ensure we're always returning an array, even if the scanner returns null or undefined
            return Array.isArray(scanResult) ? scanResult : [];
          } catch (scannerError) {
            debug(`Scanner ${name} error: ${scannerError.message}`);
            return [{
              type: `${name}_scanner_error`,
              url,
              severity: 'info',
              description: `${name} scanner failed: ${scannerError.message}`
            }];
          }
        })
      );

      results.forEach(moduleResults => {
        // Additional check to ensure moduleResults is an array
        if (Array.isArray(moduleResults)) {
          moduleResults.forEach(result => {
            if (result && typeof result === 'object') {
              if (!result.url) result.url = url;
              this.addResults([result]);
            }
          });
        }
      });
    } catch (scanError) {
      debug(`Scan URL error: ${scanError.message}`);
      this.addResults([{
        type: 'scan_url_error',
        url,
        severity: 'info',
        description: `URL scan failed: ${scanError.message}`
      }]);
    }
  }

  addResults(vulns) {
    if (!Array.isArray(vulns) || vulns.length === 0) {
      debug('addResults called with empty or non-array');
      return;
    }
    
    // Filter out any non-object values that might have snuck in
    const validVulns = vulns.filter(v => v && typeof v === 'object');
    
    if (validVulns.length === 0) return;
    
    this.results.vulnerabilities.push(...validVulns);
    
    validVulns.forEach(v => {
      this.results.summary.total++;
      if (v.severity && this.results.summary[v.severity] !== undefined) {
        this.results.summary[v.severity]++;
      } else {
        // Default to info if severity is missing or invalid
        this.results.summary.info++;
      }
    });
    
    // Debug information to help track what's being added
    debug(`Added ${validVulns.length} vulnerabilities. Total now: ${this.results.vulnerabilities.length}`);
  }

  // Add a method to get a formatted report
  getReport() {
    // Ensure we have a valid results object
    if (!this.results || !this.results.vulnerabilities) {
      return {
        error: 'No scan results available',
        timestamp: new Date().toISOString()
      };
    }
    
    // Sort vulnerabilities by severity for better presentation
    const sortOrder = { high: 0, medium: 1, low: 2, info: 3 };
    
    const sortedVulnerabilities = [...this.results.vulnerabilities].sort((a, b) => {
      return (sortOrder[a.severity] || 999) - (sortOrder[b.severity] || 999);
    });
    
    return {
      ...this.results,
      vulnerabilities: sortedVulnerabilities
    };
  }
}

module.exports = Scanner;