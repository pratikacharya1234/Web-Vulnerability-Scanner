const fetch = require('node-fetch');
const { JSDOM } = require('jsdom');
const { URL } = require('url');
const debug = require('debug')('web-vuln-scanner:crawler');
const pLimit = require('p-limit');

class Crawler {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl;
    this.baseUrlObj = new URL(this.baseUrl);
    this.depth = options.depth || 1;
    this.concurrency = options.concurrency || 5;
    this.maxPages = options.maxPages || 100; 
    this.userAgent = options.userAgent || 'WebVulnScanner/1.0';
    this.headers = options.headers || {};
    this.visitedUrls = new Set();
    this.urlsToVisit = new Set([this.baseUrl]);
    this.foundUrls = new Set([this.baseUrl]);
    this.limit = pLimit(this.concurrency);
  }

  async crawl() {
    debug(`Starting crawl: ${this.baseUrl} (depth=${this.depth}, maxPages=${this.maxPages})`);
    let currentDepth = 0;

    while (currentDepth < this.depth) {
      const urlsAtCurrentDepth = [...this.urlsToVisit].filter(url => !this.visitedUrls.has(url));
      this.urlsToVisit.clear();

      if (urlsAtCurrentDepth.length === 0 || this.foundUrls.size >= this.maxPages) break;

      const tasks = urlsAtCurrentDepth.map(url =>
        this.limit(() => this.visitUrl(url).catch(e => {
          debug(`Error visiting ${url}: ${e.message}`);
          return [];
        }))
      );

      await Promise.all(tasks);
      currentDepth++;
    }

    debug(`Crawling finished. Total URLs found: ${this.foundUrls.size}`);
    return [...this.foundUrls];
  }

  async visitUrl(url) {
    if (this.visitedUrls.has(url)) return [];
    this.visitedUrls.add(url);
    debug(`Visiting: ${url}`);

    try {
      const response = await fetch(url, {
        headers: {
          'User-Agent': this.userAgent,
          ...this.headers,
        },
        timeout: 10000,
      });

      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('text/html')) {
        debug(`Skipped non-HTML: ${url}`);
        return [];
      }

      const html = await response.text();
      const dom = new JSDOM(html, { url });
      const links = this.extractLinks(dom);

      links.forEach(link => {
        if (!this.visitedUrls.has(link)) {
          this.urlsToVisit.add(link);
          this.foundUrls.add(link);
        }
      });

      return links;
    } catch (err) {
      debug(`Fetch failed for ${url}: ${err.message}`);
      return [];
    }
  }

  extractLinks(dom) {
    const doc = dom.window.document;
    const rawLinks = [
      ...doc.querySelectorAll('a[href]'),
      ...doc.querySelectorAll('form[action]'),
      ...doc.querySelectorAll('iframe[src]'),
      ...doc.querySelectorAll('script[src]')
    ];

    const urls = [];

    for (const tag of rawLinks) {
      try {
        const attr = tag.getAttribute('href') || tag.getAttribute('action') || tag.getAttribute('src');
        if (!attr) continue;

        if (
          attr.startsWith('#') ||
          attr.startsWith('mailto:') ||
          attr.startsWith('tel:') ||
          attr.startsWith('javascript:')
        ) continue;

        const fullUrl = new URL(attr, this.baseUrl);
        if (fullUrl.hostname !== this.baseUrlObj.hostname) continue;

        const ext = fullUrl.pathname.split('.').pop().toLowerCase();
        if (['pdf','jpg','jpeg','png','gif','svg','mp3','mp4','zip','doc','docx','xls','xlsx','ppt','pptx','ico','woff','woff2'].includes(ext)) continue;

        fullUrl.hash = '';
        urls.push(fullUrl.toString());
      } catch {
        continue; 
      }
    }

    return [...new Set(urls)];
  }
}

module.exports = { Crawler };
