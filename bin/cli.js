#!/usr/bin/env node
const { program } = require('commander');
const scanner = require('../lib/index');
const fs = require('fs');
const path = require('path');
const chalk = require('chalk');
const ora = require('ora');
const { generateReport } = require('../lib/reporters/html-reporter');
const { saveMarkdownReport } = require('../lib/reporters/markdown-reporter');

program
  .name('web-vuln-scanner')
  .version('1.3.0')
  .description('🔍 Powerful CLI to scan websites for real-world vulnerabilities.')
  .argument('<url>', 'Target URL to scan (e.g., https://example.com)')
  .option('-o, --output <file>', 'Output file (e.g., report.html, output.json)')
  .option('-f, --format <format>', 'Output format: html | json | markdown | console', 'console')
  .option('-m, --modules <list>', 'Scan modules: headers,xss,sql,...', 'headers,xss,sql,ssl,ports,dirTraversal,csrf,csp,versionCheck')
  .option('--only <list>', 'Shortcut to limit to selected modules')
  .option('-t, --timeout <ms>', 'Request timeout', '15000')
  .option('-d, --depth <number>', 'Crawl depth', '2')
  .option('-c, --concurrency <number>', 'Concurrent requests', '5')
  .option('--disable-crawler', 'Only scan root URL')
  .option('--user-agent <ua>', 'User agent', 'WebVulnScanner/1.0')
  .option('--headers <json>', 'Custom headers as JSON string')
  .option('--cookies <cookies>', 'Custom Cookie header')
  .option('--open', 'Auto-open HTML report in default browser')
  .option('-v, --verbose', 'Verbose terminal output')
  .action(async (url, options) => {
    try {
      // Validate and parse modules
      const scanModules = (options.only || options.modules).split(',').map(m => m.trim());
      if (!/^https?:\/\//.test(url)) {
        console.error(chalk.red('❌ Invalid URL: must start with http:// or https://'));
        process.exit(1);
      }

      // Custom headers handling
      let customHeaders = {};
      if (options.headers) {
        try {
          customHeaders = JSON.parse(options.headers);
        } catch {
          console.error(chalk.red('❌ Invalid JSON in --headers'));
          process.exit(1);
        }
      }
      if (options.cookies) {
        customHeaders['Cookie'] = options.cookies;
      }

      const scanOptions = {
        timeout: parseInt(options.timeout),
        scanModules,
        verbose: !!options.verbose,
        depth: parseInt(options.depth),
        concurrency: parseInt(options.concurrency),
        disableCrawler: !!options.disableCrawler,
        userAgent: options.userAgent,
        headers: customHeaders
      };

      // UI output
      console.log(chalk.cyan(`\n🔎 Starting scan: ${url}`));
      console.log(chalk.gray(`Modules: ${scanModules.join(', ')}`));

      const spinner = ora('Scanning...').start();
      const results = await scanner.scan(url, scanOptions);
      spinner.succeed('✅ Scan complete');

      const report = {
        target: url,
        summary: results.summary,
        vulnerabilities: results.vulnerabilities.map(v => ({
          ...v,
          url,
          remediation: v.recommendation || 'N/A'
        }))
      };

      // Show summary
      const s = results.summary;
      console.log(chalk.magenta(`\n📊 Summary:`));
      console.log(`  🔴 High    : ${chalk.red(s.high)}`);
      console.log(`  🟠 Medium  : ${chalk.yellow(s.medium)}`);
      console.log(`  🔵 Low     : ${chalk.blue(s.low)}`);
      console.log(`  ⚪ Info    : ${chalk.gray(s.info)}`);
      console.log(`  📄 Total   : ${chalk.white.bold(s.total)}\n`);

      // Show verbose results
      if (options.verbose && options.format === 'console') {
        console.log(chalk.cyan('📋 Detailed Report:'));
        report.vulnerabilities.forEach((vuln, i) => {
          const sevColor = {
            high: chalk.red.bold,
            medium: chalk.yellow,
            low: chalk.blue,
            info: chalk.gray
          }[vuln.severity] || chalk.white;

          console.log(`\n[${i + 1}] ${sevColor(vuln.type)} (${vuln.severity.toUpperCase()})`);
          console.log(` ↪ ${vuln.description}`);
          console.log(` ↪ Recommendation: ${vuln.remediation}`);
          if (vuln.evidence) console.log(` ↪ Evidence: ${chalk.gray(vuln.evidence)}`);
        });
      }

      // Write report to file
      if (options.output) {
        const filePath = path.resolve(options.output);
        switch (options.format) {
          case 'html':
            fs.writeFileSync(filePath, generateReport(report));
            console.log(chalk.green(`✅ HTML report saved to: ${filePath}`));
            if (options.open) await import('open').then(m => m.default(filePath));
            break;
          case 'json':
            fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
            console.log(chalk.green(`✅ JSON report saved to: ${filePath}`));
            break;
          case 'markdown':
            saveMarkdownReport(filePath, report);
            console.log(chalk.green(`✅ Markdown report saved to: ${filePath}`));
            break;
          default:
            console.error(chalk.red(`❌ Unknown format: ${options.format}`));
        }
      }

    } catch (err) {
      console.error(chalk.red(`❌ Error: ${err.message}`));
      process.exit(1);
    }
  });

program.parse(process.argv);
