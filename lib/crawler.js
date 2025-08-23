const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { JSDOM } = require('jsdom');
const { URL } = require('url');
const debug = require('debug')('web-vuln-scanner:crawler');
const pLimit = require('p-limit');

class Crawler {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl;
    this.baseUrlObj = new URL(this.baseUrl);
    this.depth = options.depth || 3;
    this.concurrency = options.concurrency || 10;
    this.maxPages = options.maxPages || 1000;
    this.timeout = options.timeout || 20000;
    
    this.userAgent = options.userAgent || 'WebVulnScanner/2.0 (Security Testing)';
    this.headers = options.headers || {};
    this.cookies = options.cookies || '';
    this.followRedirects = options.followRedirects !== false;
    this.respectRobots = options.respectRobots || false;
    this.includeSubdomains = options.includeSubdomains || false;
    this.maxRetries = options.maxRetries || 2;
    this.retryDelay = options.retryDelay || 1000;

    // State management
    this.visitedUrls = new Set();
    this.urlsToVisit = new Set([this.baseUrl]);
    this.foundUrls = new Set([this.baseUrl]);
    this.failedUrls = new Set();
    this.redirectChains = new Map();
    this.pageData = new Map();
    this.formData = new Map();
    this.parameterDiscovery = new Set();

    // Initialize concurrency limiter
    try {
      this.limit = pLimit(this.concurrency);
    } catch (error) {
      this.limit = (fn) => fn();
      debug('Warning: p-limit not working, falling back to no concurrency control');
    }

    // URL patterns for comprehensive discovery
    this.commonPaths = [
      '/admin', '/administrator', '/login', '/signin', '/auth', '/panel',
      '/dashboard', '/manager', '/console', '/control', '/cp',
      '/wp-admin', '/wp-login.php', '/phpmyadmin', '/webmail',
      '/api', '/v1', '/v2', '/rest', '/graphql', '/swagger',
      '/backup', '/backups', '/temp', '/tmp', '/files', '/uploads',
      '/config', '/configuration', '/settings', '/setup', '/install',
      '/test', '/testing', '/dev', '/development', '/staging',
      '/robots.txt', '/sitemap.xml', '/.htaccess', '/.env',
      '/crossdomain.xml', '/clientaccesspolicy.xml'
    ];

    this.commonFiles = [
      'index', 'home', 'default', 'main', 'page', 'content',
      'search', 'contact', 'about', 'help', 'support',
      'profile', 'account', 'user', 'users', 'member', 'members',
      'products', 'services', 'news', 'blog', 'articles',
      'gallery', 'portfolio', 'download', 'downloads'
    ];

    this.commonExtensions = [
      '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py',
      '.html', '.htm', '.shtml', '.do', '.action', '.cfm'
    ];
  }

  async crawl() {
    debug(`Starting comprehensive crawl: ${this.baseUrl}`);
    debug(`Configuration: depth=${this.depth}, maxPages=${this.maxPages}, concurrency=${this.concurrency}`);
    
    let currentDepth = 0;

    // Phase 1: Standard crawling with depth traversal
    while (currentDepth < this.depth && this.foundUrls.size < this.maxPages) {
      const urlsAtThisDepth = [...this.urlsToVisit].filter(url => !this.visitedUrls.has(url));
      this.urlsToVisit.clear();

      if (!urlsAtThisDepth.length) break;

      debug(`Crawling depth ${currentDepth + 1}, processing ${urlsAtThisDepth.length} URLs`);

      const crawlTasks = urlsAtThisDepth.map(url =>
        this.limit(async () => {
          try {
            await this.visitUrl(url);
          } catch (err) {
            debug(`Error visiting ${url}: ${err.message}`);
            this.failedUrls.add(url);
          }
        })
      );

      await Promise.all(crawlTasks);
      currentDepth++;
    }

    // Phase 2: Directory and file enumeration
    if (this.foundUrls.size < this.maxPages) {
      debug('Starting directory and file enumeration');
      await this.performDirectoryEnumeration();
    }

    // Phase 3: Parameter discovery
    if (this.foundUrls.size < this.maxPages) {
      debug('Starting parameter discovery');
      await this.performParameterDiscovery();
    }

    // Phase 4: Technology-specific paths
    debug('Discovering technology-specific paths');
    await this.discoverTechnologyPaths();

    debug(`Crawling complete. Found ${this.foundUrls.size} URLs, ${this.failedUrls.size} failed`);
    return {
      urls: [...this.foundUrls],
      failed: [...this.failedUrls],
      pageData: Object.fromEntries(this.pageData),
      forms: Object.fromEntries(this.formData),
      parameters: [...this.parameterDiscovery],
      redirectChains: Object.fromEntries(this.redirectChains)
    };
  }

  async visitUrl(url, retryCount = 0) {
    if (this.visitedUrls.has(url) || this.foundUrls.size >= this.maxPages) return;
    
    this.visitedUrls.add(url);
    debug(`Visiting: ${url} (attempt ${retryCount + 1})`);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const requestHeaders = {
        'User-Agent': this.userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        ...this.headers
      };

      if (this.cookies) {
        requestHeaders['Cookie'] = this.cookies;
      }

      const response = await fetch(url, {
        headers: requestHeaders,
        signal: controller.signal,
        redirect: this.followRedirects ? 'follow' : 'manual',
        follow: 10
      });

      clearTimeout(timeoutId);

      // Track redirect chains
      if (response.redirected) {
        this.redirectChains.set(url, response.url);
        debug(`Redirect: ${url} -> ${response.url}`);
      }

      // Process different response types
      await this.processResponse(url, response);

    } catch (error) {
      if (retryCount < this.maxRetries && !error.name === 'AbortError') {
        debug(`Retrying ${url} in ${this.retryDelay}ms (attempt ${retryCount + 1})`);
        await this.sleep(this.retryDelay);
        return this.visitUrl(url, retryCount + 1);
      }
      
      debug(`Failed to fetch ${url}: ${error.message}`);
      this.failedUrls.add(url);
      throw error;
    }
  }

  async processResponse(url, response) {
    const contentType = response.headers.get('content-type') || '';
    const contentLength = response.headers.get('content-length');
    const statusCode = response.status;

    // Store response metadata
    this.pageData.set(url, {
      status: statusCode,
      contentType,
      contentLength: contentLength ? parseInt(contentLength) : null,
      headers: Object.fromEntries(response.headers),
      title: null,
      forms: [],
      inputs: [],
      links: []
    });

    // Handle different status codes
    if (statusCode >= 400) {
      debug(`HTTP ${statusCode} at ${url}`);
      return;
    }

    // Process HTML content
    if (contentType.toLowerCase().includes('text/html')) {
      await this.processHTMLContent(url, response);
    }
    
    // Process API responses
    else if (contentType.includes('application/json') || contentType.includes('application/xml')) {
      await this.processAPIContent(url, response);
    }
    
    // Process other content types for potential information
    else {
      await this.processOtherContent(url, response);
    }
  }

  async processHTMLContent(url, response) {
    const html = await response.text();
    let dom;

    try {
      dom = new JSDOM(html, { 
        url,
        pretendToBeVisual: false,
        resources: 'usable'
      });
    } catch (domError) {
      debug(`DOM parsing failed for ${url}: ${domError.message}`);
      return;
    }

    const doc = dom.window.document;
    const pageInfo = this.pageData.get(url);

    // Extract page title
    const titleElement = doc.querySelector('title');
    if (titleElement) {
      pageInfo.title = titleElement.textContent.trim();
    }

    // Extract and process links
    const links = this.extractLinks(dom, url);
    pageInfo.links = links;
    
    links.forEach(link => {
      if (!this.visitedUrls.has(link) && this.foundUrls.size < this.maxPages) {
        this.urlsToVisit.add(link);
        this.foundUrls.add(link);
      }
    });

    // Extract forms and inputs
    const forms = this.extractForms(doc, url);
    pageInfo.forms = forms;
    this.formData.set(url, forms);

    // Extract parameters from URLs and forms
    this.extractParameters(links, forms);

    // Look for AJAX endpoints in JavaScript
    await this.extractJavaScriptEndpoints(html, url);

    // Extract comments that might contain URLs
    this.extractCommentsEndpoints(html, url);

    this.pageData.set(url, pageInfo);
  }

  extractLinks(dom, baseUrl) {
    const doc = dom.window.document;
    const links = new Set();

    // Standard link extraction
    const linkSelectors = [
      'a[href]', 'area[href]', 'base[href]', 'link[href]',
      'form[action]', 'iframe[src]', 'frame[src]',
      'embed[src]', 'object[data]', 'source[src]',
      'track[src]', 'audio[src]', 'video[src]',
      'script[src]', 'img[src]', 'input[src]'
    ];

    linkSelectors.forEach(selector => {
      doc.querySelectorAll(selector).forEach(element => {
        const href = element.getAttribute('href') || 
                    element.getAttribute('action') || 
                    element.getAttribute('src') || 
                    element.getAttribute('data');
        
        if (href) {
          const processedUrl = this.processFoundUrl(href, baseUrl);
          if (processedUrl) links.add(processedUrl);
        }
      });
    });

    // Extract URLs from JavaScript
    const scriptTags = doc.querySelectorAll('script');
    scriptTags.forEach(script => {
      if (script.textContent) {
        this.extractUrlsFromJavaScript(script.textContent, baseUrl).forEach(url => {
          if (url) links.add(url);
        });
      }
    });

    // Extract URLs from CSS
    const styleTags = doc.querySelectorAll('style');
    styleTags.forEach(style => {
      if (style.textContent) {
        this.extractUrlsFromCSS(style.textContent, baseUrl).forEach(url => {
          if (url) links.add(url);
        });
      }
    });

    return [...links];
  }

  extractForms(doc, baseUrl) {
    const forms = [];
    
    doc.querySelectorAll('form').forEach((form, index) => {
      const formData = {
        id: form.id || `form_${index}`,
        action: form.getAttribute('action') || baseUrl,
        method: (form.getAttribute('method') || 'GET').toUpperCase(),
        enctype: form.getAttribute('enctype') || 'application/x-www-form-urlencoded',
        inputs: []
      };

      // Normalize form action URL
      try {
        formData.action = new URL(formData.action, baseUrl).toString();
      } catch (e) {
        formData.action = baseUrl;
      }

      // Extract form inputs
      form.querySelectorAll('input, textarea, select').forEach(input => {
        const inputData = {
          name: input.name || '',
          type: input.type || 'text',
          value: input.value || input.getAttribute('value') || '',
          required: input.hasAttribute('required'),
          placeholder: input.placeholder || ''
        };

        if (input.tagName === 'SELECT') {
          inputData.options = [];
          input.querySelectorAll('option').forEach(option => {
            inputData.options.push({
              value: option.value || option.textContent,
              text: option.textContent
            });
          });
        }

        formData.inputs.push(inputData);
      });

      forms.push(formData);
    });

    return forms;
  }

  extractParameters(links, forms) {
    // Extract parameters from URLs
    links.forEach(link => {
      try {
        const url = new URL(link);
        url.searchParams.forEach((value, key) => {
          this.parameterDiscovery.add(key);
        });
      } catch (e) {}
    });

    // Extract parameters from forms
    forms.forEach(form => {
      form.inputs.forEach(input => {
        if (input.name) {
          this.parameterDiscovery.add(input.name);
        }
      });
    });
  }

  async extractJavaScriptEndpoints(html, baseUrl) {
    // Common JavaScript patterns for endpoint discovery
    const patterns = [
      /['"](\/[a-zA-Z0-9\/_\-\.]*\.(?:php|asp|aspx|jsp|do|action|cgi|pl|py))['"]/g,
      /['"](\/api\/[a-zA-Z0-9\/_\-\.]*)['"]/g,
      /['"](\/[a-zA-Z0-9\/_\-]*\?[a-zA-Z0-9=&_\-]*)['"]/g,
      /url\s*:\s*['"](\/[^'"]*)['"]/g,
      /fetch\s*\(\s*['"](\/[^'"]*)['"]/g,
      /axios\.[a-z]+\s*\(\s*['"](\/[^'"]*)['"]/g,
      /\$\.(?:get|post|ajax)\s*\(\s*['"](\/[^'"]*)['"]/g
    ];

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(html)) !== null) {
        const foundPath = match[1];
        const fullUrl = this.processFoundUrl(foundPath, baseUrl);
        if (fullUrl && this.foundUrls.size < this.maxPages) {
          this.foundUrls.add(fullUrl);
          this.urlsToVisit.add(fullUrl);
        }
      }
    });
  }

  extractCommentsEndpoints(html, baseUrl) {
    // Extract URLs from HTML comments
    const commentPattern = /<!--[\s\S]*?-->/g;
    const urlPattern = /(?:href|src|action|url)=['"]?([^'"\s>]+)['"]?/gi;
    
    let commentMatch;
    while ((commentMatch = commentPattern.exec(html)) !== null) {
      const comment = commentMatch[0];
      let urlMatch;
      while ((urlMatch = urlPattern.exec(comment)) !== null) {
        const foundUrl = this.processFoundUrl(urlMatch[1], baseUrl);
        if (foundUrl && this.foundUrls.size < this.maxPages) {
          this.foundUrls.add(foundUrl);
          this.urlsToVisit.add(foundUrl);
        }
      }
    }
  }

  extractUrlsFromJavaScript(jsContent, baseUrl) {
    const urls = new Set();
    const patterns = [
      /['"`](https?:\/\/[^'"`\s]+)['"`]/g,
      /['"`](\/[^'"`\s]*?)['"`]/g,
      /window\.location\s*=\s*['"`]([^'"`]+)['"`]/g,
      /location\.href\s*=\s*['"`]([^'"`]+)['"`]/g
    ];

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(jsContent)) !== null) {
        const foundUrl = this.processFoundUrl(match[1], baseUrl);
        if (foundUrl) urls.add(foundUrl);
      }
    });

    return urls;
  }

  extractUrlsFromCSS(cssContent, baseUrl) {
    const urls = new Set();
    const pattern = /url\s*\(\s*['"`]?([^'"`\)]+)['"`]?\s*\)/g;
    
    let match;
    while ((match = pattern.exec(cssContent)) !== null) {
      const foundUrl = this.processFoundUrl(match[1], baseUrl);
      if (foundUrl) urls.add(foundUrl);
    }

    return urls;
  }

  async performDirectoryEnumeration() {
    debug('Starting directory enumeration');
    const basePathVariations = this.generatePathVariations();
    
    const enumTasks = basePathVariations.map(path =>
      this.limit(async () => {
        if (this.foundUrls.size >= this.maxPages) return;
        
        const fullUrl = new URL(path, this.baseUrl).toString();
        if (!this.visitedUrls.has(fullUrl)) {
          try {
            await this.visitUrl(fullUrl);
          } catch (error) {
            // Silent fail for directory enumeration
          }
        }
      })
    );

    await Promise.all(enumTasks);
  }

  generatePathVariations() {
    const paths = new Set();
    
    // Add common paths
    this.commonPaths.forEach(path => paths.add(path));
    
    // Generate file variations
    this.commonFiles.forEach(file => {
      paths.add(`/${file}`);
      this.commonExtensions.forEach(ext => {
        paths.add(`/${file}${ext}`);
      });
    });

    // Add discovered directory combinations
    const discoveredDirs = new Set();
    this.foundUrls.forEach(url => {
      try {
        const urlObj = new URL(url);
        const pathSegments = urlObj.pathname.split('/').filter(s => s);
        pathSegments.forEach((segment, index) => {
          if (index < pathSegments.length - 1) {
            discoveredDirs.add('/' + pathSegments.slice(0, index + 1).join('/'));
          }
        });
      } catch (e) {}
    });

    discoveredDirs.forEach(dir => {
      this.commonFiles.forEach(file => {
        this.commonExtensions.forEach(ext => {
          paths.add(`${dir}/${file}${ext}`);
        });
      });
    });

    return [...paths];
  }

  async performParameterDiscovery() {
    debug('Starting parameter discovery');
    const commonParams = [
      'id', 'page', 'user', 'name', 'search', 'query', 'q',
      'category', 'type', 'action', 'cmd', 'file', 'path',
      'url', 'redirect', 'next', 'return', 'callback',
      'debug', 'test', 'admin', 'token', 'session'
    ];

    const urlsWithParams = [...this.foundUrls].filter(url => {
      try {
        return new URL(url).search === '';
      } catch (e) {
        return false;
      }
    });

    const paramTasks = [];
    urlsWithParams.slice(0, 50).forEach(baseUrl => {
      commonParams.forEach(param => {
        paramTasks.push(
          this.limit(async () => {
            if (this.foundUrls.size >= this.maxPages) return;
            
            const testUrl = `${baseUrl}?${param}=test`;
            if (!this.visitedUrls.has(testUrl)) {
              try {
                await this.visitUrl(testUrl);
              } catch (error) {
                // Silent fail for parameter discovery
              }
            }
          })
        );
      });
    });

    await Promise.all(paramTasks);
  }

  async discoverTechnologyPaths() {
    const technologyPaths = [
      // WordPress
      '/wp-content/', '/wp-includes/', '/wp-admin/admin-ajax.php',
      '/wp-json/', '/xmlrpc.php', '/wp-cron.php',
      
      // Drupal
      '/modules/', '/themes/', '/sites/default/files/',
      '/admin/reports/status', '/user/register',
      
      // Joomla
      '/administrator/', '/components/', '/modules/',
      '/templates/', '/cache/',
      
      // PHP frameworks
      '/vendor/', '/composer.json', '/artisan',
      '/app/', '/bootstrap/', '/config/', '/storage/',
      
      // Node.js
      '/package.json', '/node_modules/', '/.env',
      '/server.js', '/app.js',
      
      // .NET
      '/bin/', '/App_Data/', '/App_Code/',
      '/web.config', '/Global.asax',
      
      // Java
      '/WEB-INF/', '/META-INF/', '/classes/',
      '/lib/', '/struts/', '/spring/',
      
      // Python
      '/static/', '/media/', '/admin/',
      '/manage.py', '/settings.py', '/wsgi.py',
      
      // Generic
      '/.git/', '/.svn/', '/.env', '/.htaccess',
      '/backup/', '/db/', '/database/', '/sql/',
      '/test/', '/tests/', '/testing/', '/dev/'
    ];

    const techTasks = technologyPaths.map(path =>
      this.limit(async () => {
        if (this.foundUrls.size >= this.maxPages) return;
        
        const fullUrl = new URL(path, this.baseUrl).toString();
        if (!this.visitedUrls.has(fullUrl)) {
          try {
            await this.visitUrl(fullUrl);
          } catch (error) {
            // Silent fail for technology discovery
          }
        }
      })
    );

    await Promise.all(techTasks);
  }

  processFoundUrl(url, baseUrl) {
    try {
      // Skip certain protocols and fragments
      if (!url || 
          url.startsWith('#') ||
          url.startsWith('mailto:') ||
          url.startsWith('tel:') ||
          url.startsWith('javascript:') ||
          url.startsWith('data:') ||
          url.startsWith('ftp:') ||
          url.startsWith('file:')) {
        return null;
      }

      // Handle relative URLs
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

      // Remove fragment
      fullUrl.hash = '';
      
      const normalizedUrl = fullUrl.toString();
      
      // Skip overly long URLs
      if (normalizedUrl.length > 2000) return null;
      
      return normalizedUrl;
      
    } catch (error) {
      debug(`Invalid URL processing: ${url} - ${error.message}`);
      return null;
    }
  }

  async processAPIContent(url, response) {
    try {
      const content = await response.text();
      
      // Try to parse JSON for endpoint discovery
      if (response.headers.get('content-type').includes('application/json')) {
        const jsonData = JSON.parse(content);
        this.extractUrlsFromJSON(jsonData, url);
      }
    } catch (error) {
      debug(`Failed to process API content at ${url}: ${error.message}`);
    }
  }

  extractUrlsFromJSON(obj, baseUrl) {
    const traverse = (current) => {
      if (typeof current === 'string' && current.match(/^\/[a-zA-Z0-9\/_\-\.]*$/)) {
        const fullUrl = this.processFoundUrl(current, baseUrl);
        if (fullUrl && this.foundUrls.size < this.maxPages) {
          this.foundUrls.add(fullUrl);
          this.urlsToVisit.add(fullUrl);
        }
      } else if (typeof current === 'object' && current !== null) {
        Object.values(current).forEach(traverse);
      }
    };
    
    traverse(obj);
  }

  async processOtherContent(url, response) {
    // Process other content types that might contain URLs
    const contentType = response.headers.get('content-type') || '';
    
    if (contentType.includes('text/') || contentType.includes('application/javascript')) {
      try {
        const content = await response.text();
        this.extractUrlsFromText(content, url);
      } catch (error) {
        debug(`Failed to process text content at ${url}: ${error.message}`);
      }
    }
  }

  extractUrlsFromText(text, baseUrl) {
    // Generic URL extraction from any text content
    const patterns = [
      /(?:href|src|action|url)=['"]([^'"]+)['"]/gi,
      /(\/[a-zA-Z0-9\/_\-\.]*(?:\?[a-zA-Z0-9=&_\-]*)?)/g
    ];

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const foundUrl = this.processFoundUrl(match[1], baseUrl);
        if (foundUrl && this.foundUrls.size < this.maxPages) {
          this.foundUrls.add(foundUrl);
          this.urlsToVisit.add(foundUrl);
        }
      }
    });
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { Crawler };