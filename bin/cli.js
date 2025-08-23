#!/usr/bin/env node
const { program } = require('commander');
const scanner = require('../lib/index');
const fs = require('fs');
const path = require('path');
const chalk = require('chalk');
const ora = require('ora');
const { generateReport } = require('../lib/reporters/html-reporter');
const { saveMarkdownReport } = require('../lib/reporters/markdown-reporter');
const { performLogin } = require('../lib/auth'); 

// Input validation
function validateUrl(url) {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('URL must use HTTP or HTTPS protocol');
    }
    return true;
  } catch (error) {
    throw new Error(`Invalid URL format: ${error.message}`);
  }
}

function validateModules(moduleList, availableModules) {
  const invalid = moduleList.filter(m => !availableModules.includes(m));
  if (invalid.length > 0) {
    throw new Error(`Invalid scan modules: ${invalid.join(', ')}`);
  }
}

function validateOutputPath(outputPath, format) {
  const dir = path.dirname(path.resolve(outputPath));
  if (!fs.existsSync(dir)) {
    throw new Error(`Output directory does not exist: ${dir}`);
  }
  
  const expectedExt = {
    html: '.html',
    json: '.json',
    markdown: '.md'
  }[format];
  
  if (expectedExt && !outputPath.endsWith(expectedExt)) {
    console.warn(chalk.yellow(`Warning: Output file should have ${expectedExt} extension for ${format} format`));
  }
}

const AVAILABLE_MODULES = [
  'headers', 'xss', 'sql', 'ssl', 'ports', 'dirTraversal', 
  'csrf', 'csp', 'versionCheck', 'rce', 'idor', 'misconfiguredHeaders'
];

const MODULE_PRESETS = {
  quick: ['headers', 'ssl', 'ports'],
  standard: ['headers', 'xss', 'sql', 'ssl', 'ports', 'csp'],
  comprehensive: AVAILABLE_MODULES
};

program
  .name('web-vuln-scanner')
  .version('1.0.8')
  .description('Advanced web application vulnerability scanner for security professionals and developers')
  .argument('<url>', 'Target URL to scan (must include protocol: https://example.com)')
  .option('-o, --output <file>', 'Output file path (supports .html, .json, .md extensions)')
  .option('-f, --format <format>', 'Report format: html | json | markdown | console', 'console')
  .option('-m, --modules <list>', 'Comma-separated list of scan modules', AVAILABLE_MODULES.join(','))
  .option('--only <list>', 'Override modules - scan only specified modules')
  .option('-t, --timeout <ms>', 'HTTP request timeout in milliseconds', '15000')
  .option('-d, --depth <number>', 'Maximum crawling depth (0 disables crawling)', '2')
  .option('-c, --concurrency <number>', 'Number of concurrent HTTP requests', '5')
  .option('--max-pages <number>', 'Maximum pages to crawl per domain', '100')
  .option('--disable-crawler', 'Skip crawling - scan only the target URL')
  .option('--user-agent <string>', 'Custom User-Agent header', 'WebVulnScanner/1.0.8')
  .option('--headers <json>', 'Custom HTTP headers as JSON string')
  .option('--cookies <string>', 'Custom Cookie header value')
  .option('--proxy <url>', 'HTTP/HTTPS proxy URL (e.g., http://proxy:8080)')
  .option('--auth-header <header>', 'Authorization header (e.g., "Bearer token123")')
  .option('--open', 'Automatically open HTML report in default browser')
  .option('-v, --verbose', 'Enable verbose logging and detailed output')
  .option('--silent', 'Suppress all output except errors')
  .option('--quick', `Quick scan preset: ${MODULE_PRESETS.quick.join(', ')}`)
  .option('--standard', `Standard scan preset: ${MODULE_PRESETS.standard.join(', ')}`)
  .option('--comprehensive', `Comprehensive scan preset: all available modules`)
  .option('--risk-scoring', 'Include CVSS-like risk scores in findings')
  .option('--compliance-check', 'Add compliance framework mappings (OWASP Top 10, CWE)')
  .option('--include-evidence', 'Include technical evidence and payloads in reports')
  .option('--exclude-domains <list>', 'Comma-separated domains to exclude from crawling')
  .option('--include-domains <list>', 'Comma-separated domains to include in crawling')
  .option('--login-url <url>', 'Login endpoint URL for form-based authentication')
  .option('--username <username>', 'Username for authentication')
  .option('--password <password>', 'Password for authentication')
  .option('--login-data <json>', 'Login form data as JSON string')
  .option('--session-file <path>', 'File to save/load session cookies')
  .option('--retry-attempts <number>', 'Number of retry attempts for failed requests', '3')
  .option('--rate-limit <ms>', 'Delay between requests in milliseconds', '0')
  .addHelpText('after', `
Examples:
  $ web-vuln-scanner https://example.com
  $ web-vuln-scanner https://example.com --quick -o report.html -f html
  $ web-vuln-scanner https://example.com --only xss,sql --depth 3 --verbose
  $ web-vuln-scanner https://example.com --login-url /login --username admin --password pass
  $ web-vuln-scanner https://example.com --headers '{"API-Key":"abc123"}' --proxy http://127.0.0.1:8080
  
Available Modules: ${AVAILABLE_MODULES.join(', ')}

For detailed documentation: https://github.com/your-repo/web-vuln-scanner`)
  .action(async (url, options) => {
    const startTime = Date.now();
    
    try {
      // Input validation
      validateUrl(url);
      
      // Determine scan modules
      let scanModules;
      if (options.quick) {
        scanModules = MODULE_PRESETS.quick;
      } else if (options.standard) {
        scanModules = MODULE_PRESETS.standard;
      } else if (options.comprehensive) {
        scanModules = MODULE_PRESETS.comprehensive;
      } else {
        const moduleString = options.only || options.modules;
        scanModules = moduleString.split(',').map(m => m.trim()).filter(Boolean);
      }
      
      validateModules(scanModules, AVAILABLE_MODULES);
      
      // Validate output options
      if (options.output) {
        validateOutputPath(options.output, options.format);
      }
      
      // Parse custom headers
      let customHeaders = {};
      if (options.headers) {
        try {
          customHeaders = JSON.parse(options.headers);
        } catch (error) {
          throw new Error(`Invalid JSON format in --headers: ${error.message}`);
        }
      }
      
      if (options.cookies) {
        customHeaders['Cookie'] = options.cookies;
      }
      
      if (options.authHeader) {
        customHeaders['Authorization'] = options.authHeader;
      }

      // Authentication handling
      if (options.loginUrl && options.username && options.password) {
        if (!options.silent) console.log(chalk.yellow('Performing authentication...'));
        
        const loginData = options.loginData ? 
          JSON.parse(options.loginData) : 
          { username: options.username, password: options.password };
        
        const loginResult = await performLogin(options.loginUrl, loginData, customHeaders);
        
        if (!loginResult.success) {
          throw new Error(`Authentication failed: ${loginResult.error || 'Invalid credentials'}`);
        }
        
        if (!options.silent) console.log(chalk.green('Authentication successful - session established'));
        customHeaders = { ...customHeaders, ...loginResult.headers };
        
        // Save session if requested
        if (options.sessionFile) {
          fs.writeFileSync(options.sessionFile, JSON.stringify(loginResult.headers, null, 2));
        }
      }

      // Load session from file
      if (options.sessionFile && fs.existsSync(options.sessionFile)) {
        try {
          const sessionData = JSON.parse(fs.readFileSync(options.sessionFile, 'utf8'));
          customHeaders = { ...customHeaders, ...sessionData };
          if (!options.silent) console.log(chalk.blue('Loaded session from file'));
        } catch (error) {
          console.warn(chalk.yellow(`Warning: Could not load session file: ${error.message}`));
        }
      }

      // Build scan configuration
      const scanOptions = {
        timeout: parseInt(options.timeout),
        scanModules,
        verbose: !!options.verbose && !options.silent,
        depth: parseInt(options.depth),
        concurrency: parseInt(options.concurrency),
        maxPages: parseInt(options.maxPages),
        disableCrawler: !!options.disableCrawler,
        userAgent: options.userAgent,
        headers: customHeaders,
        proxy: options.proxy,
        retryAttempts: parseInt(options.retryAttempts),
        rateLimit: parseInt(options.rateLimit),
        excludeDomains: options.excludeDomains ? options.excludeDomains.split(',').map(d => d.trim()) : [],
        includeDomains: options.includeDomains ? options.includeDomains.split(',').map(d => d.trim()) : []
      };

      // Display scan configuration
      if (!options.silent) {
        console.log(chalk.cyan('\nScan Configuration:'));
        console.log(chalk.gray(`Target: ${url}`));
        console.log(chalk.gray(`Modules: ${scanModules.join(', ')}`));
        console.log(chalk.gray(`Depth: ${options.depth} | Concurrency: ${options.concurrency}`));
        console.log(chalk.gray(`Timeout: ${options.timeout}ms | Rate Limit: ${options.rateLimit}ms`));
        if (options.proxy) console.log(chalk.gray(`Proxy: ${options.proxy}`));
        console.log('');
      }

      // Execute scan
      const spinner = options.silent ? null : ora('Initializing scanner...').start();
      
      try {
        if (spinner) spinner.text = 'Scanning for vulnerabilities...';
        const results = await scanner.scan(url, scanOptions);
        
        if (spinner) spinner.succeed('Vulnerability scan completed');

        // Process results
        const report = {
          metadata: {
            target: url,
            scanDate: new Date().toISOString(),
            scanDuration: Math.round((Date.now() - startTime) / 1000),
            version: '1.0.8',
            modules: scanModules,
            configuration: {
              depth: options.depth,
              concurrency: options.concurrency,
              timeout: options.timeout
            }
          },
          summary: results.summary,
          vulnerabilities: results.vulnerabilities.map(vuln => ({
            ...vuln,
            target: url,
            remediation: vuln.recommendation || 'No specific remediation available',
            ...(options.riskScoring && { 
              riskScore: calculateRiskScore(vuln),
              cvssVector: generateCVSSVector(vuln)
            }),
            ...(options.complianceCheck && { 
              owaspMapping: mapToOWASP(vuln.type),
              cweId: mapToCWE(vuln.type)
            }),
            ...(options.includeEvidence && { 
              evidence: vuln.evidence || 'No evidence captured',
              payload: vuln.payload || null
            })
          }))
        };

        // Display summary
        if (!options.silent) {
          const { summary } = results;
          console.log(chalk.magenta('\nVulnerability Summary:'));
          console.log(`  Critical: ${chalk.red.bold(summary.critical || 0)}`);
          console.log(`  High    : ${chalk.red(summary.high || 0)}`);
          console.log(`  Medium  : ${chalk.yellow(summary.medium || 0)}`);
          console.log(`  Low     : ${chalk.blue(summary.low || 0)}`);
          console.log(`  Info    : ${chalk.gray(summary.info || 0)}`);
          console.log(`  Total   : ${chalk.white.bold(summary.total || 0)}`);
          console.log(chalk.gray(`\nScan Duration: ${Math.round((Date.now() - startTime) / 1000)}s`));
        }

        // Verbose console output
        if (options.verbose && options.format === 'console' && !options.silent) {
          displayVulnerabilities(report.vulnerabilities);
        }

        // Save report
        if (options.output) {
          await saveReport(options.output, options.format, report, options.open, options.silent);
        }

        // Exit code based on findings
        if (results.summary.high > 0 || results.summary.critical > 0) {
          process.exit(2); // High/Critical findings
        } else if (results.summary.medium > 0) {
          process.exit(1); // Medium findings
        }
        // Exit 0 for low/info only

      } catch (scanError) {
        if (spinner) spinner.fail('Scan failed');
        throw scanError;
      }

    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      if (options.verbose) {
        console.error(chalk.red('Stack trace:'));
        console.error(error.stack);
      }
      process.exit(3);
    }
  });

// Helper functions
function calculateRiskScore(vulnerability) {
  const baseScores = { critical: 9.0, high: 7.0, medium: 4.0, low: 2.0, info: 0.0 };
  return baseScores[vulnerability.severity] || 0.0;
}

function generateCVSSVector(vulnerability) {
  // Simplified CVSS vector generation
  return `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`;
}

function mapToOWASP(vulnerabilityType) {
  const mappings = {
    xss: 'A03:2021 – Injection',
    sql: 'A03:2021 – Injection', 
    csrf: 'A01:2021 – Broken Access Control',
    headers: 'A05:2021 – Security Misconfiguration'
  };
  return mappings[vulnerabilityType] || 'Not Mapped';
}

function mapToCWE(vulnerabilityType) {
  const mappings = {
    xss: 'CWE-79',
    sql: 'CWE-89',
    csrf: 'CWE-352',
    headers: 'CWE-16'
  };
  return mappings[vulnerabilityType] || null;
}

function displayVulnerabilities(vulnerabilities) {
  console.log(chalk.cyan('\nDetailed Findings:'));
  vulnerabilities.forEach((vuln, index) => {
    const severityColor = {
      critical: chalk.magenta.bold,
      high: chalk.red.bold,
      medium: chalk.yellow,
      low: chalk.blue,
      info: chalk.gray
    }[vuln.severity] || chalk.white;

    console.log(`\n[${index + 1}] ${severityColor(vuln.type)} - ${vuln.severity.toUpperCase()}`);
    console.log(`    Description: ${vuln.description}`);
    console.log(`    Location: ${vuln.url || vuln.location || 'N/A'}`);
    console.log(`    Remediation: ${vuln.remediation}`);
    
    if (vuln.owaspMapping) console.log(`    OWASP: ${vuln.owaspMapping}`);
    if (vuln.cweId) console.log(`    CWE: ${vuln.cweId}`);
    if (vuln.riskScore) console.log(`    Risk Score: ${vuln.riskScore}/10`);
  });
}

async function saveReport(outputPath, format, report, autoOpen, silent) {
  const filePath = path.resolve(outputPath);
  
  try {
    switch (format) {
      case 'html':
        fs.writeFileSync(filePath, generateReport(report));
        if (!silent) console.log(chalk.green(`HTML report saved: ${filePath}`));
        if (autoOpen) {
          const open = await import('open');
          await open.default(filePath);
        }
        break;
      case 'json':
        fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
        if (!silent) console.log(chalk.green(`JSON report saved: ${filePath}`));
        break;
      case 'markdown':
        saveMarkdownReport(filePath, report);
        if (!silent) console.log(chalk.green(`Markdown report saved: ${filePath}`));
        break;
      default:
        fs.writeFileSync(filePath, generateReport(report));
        if (!silent) console.log(chalk.green(`Report saved: ${filePath}`));
    }
  } catch (error) {
    throw new Error(`Failed to save report: ${error.message}`);
  }
}

program.parse(process.argv);