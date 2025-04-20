module.exports = {
    scan: async (page, url) => {
      const missing = [];
      if (!page.headers['x-frame-options']) missing.push('X-Frame-Options');
      if (!page.headers['x-content-type-options']) missing.push('X-Content-Type-Options');
  
      if (missing.length) {
        return [{
          type: 'Missing Security Headers',
          severity: 'low',
          url,
          description: `The following headers are missing: ${missing.join(', ')}`,
          recommendation: 'Add common security headers to improve baseline protection.',
          evidence: JSON.stringify(missing)
        }];
      }
      return [];
    }
  };
  