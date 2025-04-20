const cheerio = require('cheerio');

module.exports = {
  scan: async (page, url) => {
    const vulnerabilities = [];

    try {
      const { content } = page;
      const $ = cheerio.load(content);

      // Check common JS libraries with version numbers
      const scripts = $('script[src]');

      scripts.each((_, script) => {
        const src = $(script).attr('src');
        const matches = src.match(/\b([a-zA-Z]+)[-.]?((\d+\.)?(\d+\.)?(\*|\d+))\.(min\.)?js\b/);

        if (matches) {
          const lib = matches[1];
          const version = matches[2];

          vulnerabilities.push({
            type: 'Outdated Library Detected',
            severity: 'medium',
            url,
            description: `Possible outdated or exposed version of ${lib}.js - v${version}`,
            recommendation: `Check if ${lib} v${version} is the latest stable version and update if necessary.`,
            evidence: src
          });
        }
      });

      return vulnerabilities;

    } catch (err) {
      return [{
        type: 'version-check-error',
        severity: 'info',
        url,
        description: 'Failed to analyze script versions.',
        recommendation: 'Inspect manually for outdated JS libraries.',
        evidence: err.message
      }];
    }
  }
};
