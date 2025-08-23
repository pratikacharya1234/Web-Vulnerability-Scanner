const puppeteer = require('puppeteer');
const { URL } = require('url');
const debug = require('debug')('web-vuln-scanner:puppeteer');

class PuppeteerCrawler {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl;
    this.baseUrlObj = new URL(this.baseUrl);
    this.depth = options.depth || 3;
    this.maxPages = options.maxPages || 500;
    this.timeout = options.timeout || 30000;
    this.userAgent = options.userAgent || 'WebVulnScanner/2.0 (Security Testing)';
    this.headers = options.headers || {};
    this.cookies = options.cookies || [];
    this.includeSubdomains = options.includeSubdomains || false;
    this.screenshot = options.screenshot || false;
    this.interceptRequests = options.interceptRequests !== false;
    this.waitForJs = options.waitForJs || 3000;
    this.maxRetries = options.maxRetries || 2;

    // State management
    this.visited = new Set();
    this.queue = [this.baseUrl];
    this.foundUrls = new Set([this.baseUrl]);
    this.failedUrls = new Set();
    this.pageData = new Map();
    this.formData = new Map();
    this.ajaxEndpoints = new Set();
    this.websocketEndpoints = new Set();
    this.apiEndpoints = new Set();
    this.jsErrors = new Map();
    this.networkRequests = new Map();
    
    // Browser management
    this.browser = null;
    this.activeTabs = new Set();
  }

  async initBrowser() {
    if (!this.browser) {
      debug('Launching browser with enhanced configuration');
      
      this.browser = await puppeteer.launch({
        headless: 'new',
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu',
          '--disable-web-security',
          '--disable-features=VizDisplayCompositor',
          '--disable-background-timer-throttling',
          '--disable-backgrounding-occluded-windows',
          '--disable-renderer-backgrounding',
          '--disable-field-trial-config',
          '--disable-ipc-flooding-protection'
        ],
        timeout: 60000,
        ignoreDefaultArgs: ['--disable-extensions']
      });

      // Handle browser disconnect
      this.browser.on('disconnected', () => {
        debug('Browser disconnected');
        this.browser = null;
      });
    }
    
    return this.browser;
  }

  async createPage() {
    const browser = await this.initBrowser();
    const page = await browser.newPage();
    this.activeTabs.add(page);

    // Enhanced page configuration
    await page.setViewport({ width: 1366, height: 768 });
    await page.setUserAgent(this.userAgent);

    // Set extra headers
    if (Object.keys(this.headers).length > 0) {
      await page.setExtraHTTPHeaders(this.headers);
    }

    // Set cookies
    if (this.cookies.length > 0) {
      await page.setCookie(...this.cookies);
    }

    // Request/response interception for comprehensive monitoring
    if (this.interceptRequests) {
      await page.setRequestInterception(true);
      
      page.on('request', (request) => {
        // Log all requests for endpoint discovery
        const url = request.url();
        const method = request.method();
        
        if (this.isRelevantEndpoint(url)) {
          this.networkRequests.set(url, {
            method,
            headers: request.headers(),
            postData: request.postData(),
            timestamp: Date.now()
          });

          // Detect API endpoints
          if (this.isApiEndpoint(url)) {
            this.apiEndpoints.add(url);
          }
        }

        request.continue();
      });

      page.on('response', (response) => {
        const url = response.url();
        const status = response.status();
        
        if (this.networkRequests.has(url)) {
          const requestData = this.networkRequests.get(url);
          requestData.status = status;
          requestData.responseHeaders = response.headers();
          this.networkRequests.set(url, requestData);
        }
      });
    }

    // Console message monitoring for errors and endpoints
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const url = page.url();
        if (!this.jsErrors.has(url)) {
          this.jsErrors.set(url, []);
        }
        this.jsErrors.get(url).push(msg.text());
      }
    });

    // Page error monitoring
    page.on('pageerror', (error) => {
      const url = page.url();
      if (!this.jsErrors.has(url)) {
        this.jsErrors.set(url, []);
      }
      this.jsErrors.get(url).push(error.message);
    });

    return page;
  }

  async closePage(page) {
    try {
      this.activeTabs.delete(page);
      await page.close();
    } catch (error) {
      debug(`Error closing page: ${error.message}`);
    }
  }

  async closeBrowser() {
    if (this.browser) {
      try {
        // Close all active tabs
        for (const page of this.activeTabs) {
          await this.closePage(page);
        }
        
        await this.browser.close();
        this.browser = null;
      } catch (error) {
        debug(`Error closing browser: ${error.message}`);
      }
    }
  }

  async crawl() {
    debug(`Starting comprehensive Puppeteer crawl: ${this.baseUrl}`);
    debug(`Configuration: depth=${this.depth}, maxPages=${this.maxPages}, timeout=${this.timeout}`);

    try {
      let currentDepth = 0;

      while (this.queue.length && this.visited.size < this.maxPages && currentDepth < this.depth) {
        const currentLevelUrls = [...this.queue];
        this.queue = [];

        debug(`Processing depth ${currentDepth + 1}, ${currentLevelUrls.length} URLs`);

        // Process URLs in batches to manage resources
        const batchSize = 3;
        for (let i = 0; i < currentLevelUrls.length; i += batchSize) {
          const batch = currentLevelUrls.slice(i, i + batchSize);
          const promises = batch.map(url => this.crawlPage(url));
          
          try {
            await Promise.allSettled(promises);
          } catch (error) {
            debug(`Batch processing error: ${error.message}`);
          }

          // Small delay between batches to avoid overwhelming the target
          await this.sleep(500);
        }

        currentDepth++;
      }

      // Additional discovery phases
      await this.discoverHiddenEndpoints();
      await this.performInteractiveDiscovery();

      debug(`Puppeteer crawl complete. Found ${this.foundUrls.size} URLs, ${this.failedUrls.size} failed`);
      
      return {
        urls: [...this.foundUrls],
        failed: [...this.failedUrls],
        pageData: Object.fromEntries(this.pageData),
        forms: Object.fromEntries(this.formData),
        ajaxEndpoints: [...this.ajaxEndpoints],
        apiEndpoints: [...this.apiEndpoints],
        websocketEndpoints: [...this.websocketEndpoints],
        networkRequests: Object.fromEntries(this.networkRequests),
        jsErrors: Object.fromEntries(this.jsErrors)
      };

    } finally {
      await this.closeBrowser();
    }
  }

  async crawlPage(url, retryCount = 0) {
    if (this.visited.has(url) || this.foundUrls.size >= this.maxPages) {
      return;
    }

    this.visited.add(url);
    debug(`Crawling: ${url} (attempt ${retryCount + 1})`);

    let page;
    try {
      page = await this.createPage();

      // Navigate to the page with comprehensive waiting
      const response = await page.goto(url, {
        waitUntil: ['networkidle0', 'domcontentloaded'],
        timeout: this.timeout
      });

      if (!response) {
        throw new Error('No response received');
      }

      const status = response.status();
      if (status >= 400) {
        debug(`HTTP ${status} at ${url}`);
        this.failedUrls.add(url);
        return;
      }

      // Wait for JavaScript execution and dynamic content
      await page.waitForTimeout(this.waitForJs);

      // Extract comprehensive page data
      await this.extractPageData(page, url);

      // Take screenshot if enabled
      if (this.screenshot && this.foundUrls.size < 20) {
        try {
          await page.screenshot({
            path: `screenshots/${this.sanitizeFilename(url)}.png`,
            fullPage: true
          });
        } catch (screenshotError) {
          debug(`Screenshot failed for ${url}: ${screenshotError.message}`);
        }
      }

    } catch (error) {
      if (retryCount < this.maxRetries) {
        debug(`Retrying ${url} (attempt ${retryCount + 2})`);
        await this.sleep(2000);
        return this.crawlPage(url, retryCount + 1);
      }
      
      debug(`Failed to crawl ${url}: ${error.message}`);
      this.failedUrls.add(url);
    } finally {
      if (page) {
        await this.closePage(page);
      }
    }
  }

  async extractPageData(page, url) {
    try {
      // Execute comprehensive data extraction in browser context
      const pageInfo = await page.evaluate(() => {
        const data = {
          title: document.title,
          url: window.location.href,
          links: [],
          forms: [],
          inputs: [],
          buttons: [],
          iframes: [],
          scripts: [],
          websockets: [],
          eventListeners: [],
          localStorage: {},
          sessionStorage: {},
          cookies: document.cookie,
          meta: []
        };

        // Extract all links
        document.querySelectorAll('a[href], area[href]').forEach((link, index) => {
          data.links.push({
            href: link.href,
            text: link.textContent?.trim() || '',
            title: link.title || '',
            target: link.target || '',
            rel: link.rel || ''
          });
        });

        // Extract forms with detailed information
        document.querySelectorAll('form').forEach((form, index) => {
          const formData = {
            id: form.id || `form_${index}`,
            action: form.action || window.location.href,
            method: form.method?.toUpperCase() || 'GET',
            enctype: form.enctype || 'application/x-www-form-urlencoded',
            target: form.target || '',
            inputs: []
          };

          // Extract all form controls
          form.querySelectorAll('input, textarea, select, button').forEach(input => {
            const inputData = {
              name: input.name || '',
              type: input.type || 'text',
              value: input.value || '',
              placeholder: input.placeholder || '',
              required: input.required || false,
              disabled: input.disabled || false,
              readonly: input.readOnly || false,
              id: input.id || '',
              className: input.className || ''
            };

            if (input.tagName === 'SELECT') {
              inputData.options = [];
              input.querySelectorAll('option').forEach(option => {
                inputData.options.push({
                  value: option.value,
                  text: option.textContent,
                  selected: option.selected
                });
              });
            }

            formData.inputs.push(inputData);
          });

          data.forms.push(formData);
        });

        // Extract all clickable elements
        document.querySelectorAll('button, input[type="button"], input[type="submit"], [onclick]').forEach(button => {
          data.buttons.push({
            text: button.textContent?.trim() || button.value || '',
            type: button.type || '',
            onclick: button.getAttribute('onclick') || '',
            id: button.id || '',
            className: button.className || ''
          });
        });

        // Extract iframes
        document.querySelectorAll('iframe, frame').forEach(iframe => {
          data.iframes.push({
            src: iframe.src || '',
            name: iframe.name || '',
            id: iframe.id || ''
          });
        });

        // Extract script sources
        document.querySelectorAll('script[src]').forEach(script => {
          data.scripts.push(script.src);
        });

        // Extract meta information
        document.querySelectorAll('meta').forEach(meta => {
          data.meta.push({
            name: meta.name || meta.getAttribute('property') || '',
            content: meta.content || '',
            httpEquiv: meta.httpEquiv || ''
          });
        });

        // Extract storage data (if accessible)
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            data.localStorage[key] = localStorage.getItem(key);
          }
        } catch (e) {}

        try {
          for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            data.sessionStorage[key] = sessionStorage.getItem(key);
          }
        } catch (e) {}

        return data;
      });

      // Store page data
      this.pageData.set(url, pageInfo);
      this.formData.set(url, pageInfo.forms);

      // Process discovered links
      pageInfo.links.forEach(link => {
        const processedUrl = this.processFoundUrl(link.href, url);
        if (processedUrl && !this.visited.has(processedUrl)) {
          this.foundUrls.add(processedUrl);
          this.queue.push(processedUrl);
        }
      });

      // Process form actions
      pageInfo.forms.forEach(form => {
        const processedUrl = this.processFoundUrl(form.action, url);
        if (processedUrl && !this.visited.has(processedUrl)) {
          this.foundUrls.add(processedUrl);
          this.queue.push(processedUrl);
        }
      });

      // Extract AJAX endpoints from page
      await this.extractAjaxEndpoints(page, url);

      // Look for WebSocket connections
      await this.extractWebSocketEndpoints(page, url);

    } catch (error) {
      debug(`Error extracting page data from ${url}: ${error.message}`);
    }
  }

  async extractAjaxEndpoints(page, url) {
    try {
      // Override XMLHttpRequest and fetch to capture AJAX calls
      await page.evaluateOnNewDocument(() => {
        window.capturedRequests = [];
        
        // Intercept XMLHttpRequest
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
          window.capturedRequests.push({ type: 'xhr', method, url });
          return originalXHROpen.apply(this, arguments);
        };

        // Intercept fetch
        const originalFetch = window.fetch;
        window.fetch = function(input, init) {
          const url = typeof input === 'string' ? input : input.url;
          const method = init?.method || 'GET';
          window.capturedRequests.push({ type: 'fetch', method, url });
          return originalFetch.apply(this, arguments);
        };
      });

      // Trigger common AJAX patterns by interacting with the page
      await this.triggerAjaxCalls(page);

      // Extract captured requests
      const capturedRequests = await page.evaluate(() => window.capturedRequests || []);
      
      capturedRequests.forEach(request => {
        const processedUrl = this.processFoundUrl(request.url, url);
        if (processedUrl) {
          this.ajaxEndpoints.add(processedUrl);
          if (!this.visited.has(processedUrl)) {
            this.foundUrls.add(processedUrl);
            this.queue.push(processedUrl);
          }
        }
      });

    } catch (error) {
      debug(`Error extracting AJAX endpoints from ${url}: ${error.message}`);
    }
  }

  async triggerAjaxCalls(page) {
    try {
      // Click on buttons and links that might trigger AJAX
      const clickableElements = await page.$('button, [onclick], .ajax, [data-ajax], [data-url]');
      
      for (let element of clickableElements.slice(0, 5)) {
        try {
          await Promise.race([
            element.click(),
            page.waitForTimeout(1000)
          ]);
          await page.waitForTimeout(500);
        } catch (e) {}
      }

      // Trigger form submissions
      const forms = await page.$('form');
      for (let form of forms.slice(0, 3)) {
        try {
          await page.evaluate(form => {
            // Fill form with test data
            const inputs = form.querySelectorAll('input[type="text"], input[type="email"], textarea');
            inputs.forEach(input => {
              if (input.type === 'email') {
                input.value = 'test@example.com';
              } else {
                input.value = 'test';
              }
            });
          }, form);
          
          const submitButton = await form.$('input[type="submit"], button[type="submit"], button');
          if (submitButton) {
            await Promise.race([
              submitButton.click(),
              page.waitForTimeout(1000)
            ]);
            await page.waitForTimeout(1000);
          }
        } catch (e) {}
      }

    } catch (error) {
      debug(`Error triggering AJAX calls: ${error.message}`);
    }
  }

  async extractWebSocketEndpoints(page, url) {
    try {
      // Override WebSocket constructor to capture connections
      await page.evaluateOnNewDocument(() => {
        window.capturedWebSockets = [];
        const originalWebSocket = window.WebSocket;
        
        window.WebSocket = function(url, protocols) {
          window.capturedWebSockets.push({ url, protocols });
          return new originalWebSocket(url, protocols);
        };
      });

      // Wait for any WebSocket connections to be established
      await page.waitForTimeout(2000);

      const webSockets = await page.evaluate(() => window.capturedWebSockets || []);
      
      webSockets.forEach(ws => {
        const processedUrl = this.processFoundUrl(ws.url, url);
        if (processedUrl) {
          this.websocketEndpoints.add(processedUrl);
        }
      });

    } catch (error) {
      debug(`Error extracting WebSocket endpoints from ${url}: ${error.message}`);
    }
  }

  async discoverHiddenEndpoints(page) {
    debug('Discovering hidden endpoints through JavaScript analysis');
    
    const commonEndpoints = [
      '/api/v1/', '/api/v2/', '/rest/', '/graphql', '/swagger',
      '/admin/api/', '/backend/', '/internal/', '/private/',
      '/debug/', '/test/', '/dev/', '/.well-known/'
    ];

    for (const endpoint of commonEndpoints) {
      if (this.foundUrls.size >= this.maxPages) break;
      
      const testUrl = new URL(endpoint, this.baseUrl).toString();
      if (!this.visited.has(testUrl)) {
        this.foundUrls.add(testUrl);
        this.queue.push(testUrl);
      }
    }
  }

  async performInteractiveDiscovery() {
    debug('Performing interactive discovery on key pages');
    
    // Get pages that are likely to have dynamic content
    const interactivePages = [...this.foundUrls]
      .filter(url => {
        const path = new URL(url).pathname.toLowerCase();
        return path.includes('admin') || 
               path.includes('dashboard') || 
               path.includes('panel') || 
               path.includes('manage') ||
               path === '/' ||
               path.includes('login');
      })
      .slice(0, 5);

    for (const url of interactivePages) {
      if (this.foundUrls.size >= this.maxPages) break;
      
      let page;
      try {
        page = await this.createPage();
        await page.goto(url, { waitUntil: 'networkidle0' });
        
        // Perform comprehensive interaction
        await this.performPageInteraction(page);
        
      } catch (error) {
        debug(`Error in interactive discovery for ${url}: ${error.message}`);
      } finally {
        if (page) {
          await this.closePage(page);
        }
      }
    }
  }

  async performPageInteraction(page) {
    try {
      // Hover over menu items to reveal submenus
      const menuItems = await page.$('nav a, .menu a, .navbar a, [role="menuitem"]');
      for (let item of menuItems.slice(0, 10)) {
        try {
          await item.hover();
          await page.waitForTimeout(200);
        } catch (e) {}
      }

      // Click on tabs and accordions
      const tabElements = await page.$('[role="tab"], .tab, .accordion-header, .toggle');
      for (let tab of tabElements.slice(0, 5)) {
        try {
          await tab.click();
          await page.waitForTimeout(500);
        } catch (e) {}
      }

      // Interact with dropdowns
      const dropdowns = await page.$('select, .dropdown-toggle, [data-toggle="dropdown"]');
      for (let dropdown of dropdowns.slice(0, 5)) {
        try {
          await dropdown.click();
          await page.waitForTimeout(300);
        } catch (e) {}
      }

    } catch (error) {
      debug(`Error during page interaction: ${error.message}`);
    }
  }

  processFoundUrl(url, baseUrl) {
    try {
      if (!url || 
          url.startsWith('#') ||
          url.startsWith('mailto:') ||
          url.startsWith('tel:') ||
          url.startsWith('javascript:') ||
          url.startsWith('data:')) {
        return null;
      }

      const fullUrl = new URL(url, baseUrl);
      
      // Domain filtering
      if (!this.includeSubdomains) {
        if (fullUrl.hostname !== this.baseUrlObj.hostname) {
          return null;
        }
      } else {
        if (!fullUrl.hostname.endsWith(this.baseUrlObj.hostname)) {
          return null;
        }
      }

      fullUrl.hash = '';
      const normalizedUrl = fullUrl.toString();
      
      if (normalizedUrl.length > 2000) return null;
      
      return normalizedUrl;
      
    } catch (error) {
      return null;
    }
  }

  isRelevantEndpoint(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname === this.baseUrlObj.hostname ||
             (this.includeSubdomains && urlObj.hostname.endsWith(this.baseUrlObj.hostname));
    } catch (e) {
      return false;
    }
  }

  isApiEndpoint(url) {
    const apiPatterns = [
      '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/',
      '.json', '.xml', '/ajax/', '/rpc/', '/soap/'
    ];
    
    return apiPatterns.some(pattern => url.includes(pattern));
  }

  sanitizeFilename(url) {
    return url.replace(/[^a-z0-9]/gi, '_').toLowerCase().substring(0, 50);
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Standalone crawl function for backward compatibility
async function crawlPage(url, options = {}) {
  const crawler = new PuppeteerCrawler({
    baseUrl: url,
    maxPages: options.maxPages || 20,
    timeout: options.timeout || 15000,
    userAgent: options.userAgent,
    headers: options.headers,
    cookies: options.cookies
  });
  
  const results = await crawler.crawl();
  return results.urls;
}

module.exports = { PuppeteerCrawler, crawlPage };