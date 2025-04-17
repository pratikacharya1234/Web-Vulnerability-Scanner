/**
 * Content Security Policy scanner
 */
async function scan(page, url) {
    const results = [];
    const { headers } = page;
    
    // Check for CSP header
    const cspHeader = 
      headers['content-security-policy'] || 
      headers['Content-Security-Policy'] ||
      headers['x-content-security-policy'] ||
      headers['X-Content-Security-Policy'];
    
    if (!cspHeader) {
      results.push({
        type: 'missing_csp',
        description: 'Content Security Policy header is missing.',
        recommendation: 'Implement a Content Security Policy header to help prevent XSS and other code injection attacks.',
        severity: 'medium',
        evidence: 'No CSP header found',
        details: 'CSP helps mitigate XSS attacks by restricting which resources can be loaded and executed.'
      });
      return results;
    }
    
    // Check CSP directives
    const directives = parseCSP(cspHeader);
    
    // Check for unsafe-inline in script-src or default-src
    if ((directives['script-src'] && directives['script-src'].includes("'unsafe-inline'")) ||
        (!directives['script-src'] && directives['default-src'] && directives['default-src'].includes("'unsafe-inline'"))) {
      results.push({
        type: 'unsafe_csp_directive',
        description: "CSP allows 'unsafe-inline' scripts which negates much of the XSS protection.",
        recommendation: "Remove 'unsafe-inline' from script-src and use nonces or hashes instead.",
        severity: 'high',
        evidence: cspHeader,
        details: "'unsafe-inline' allows inline scripts to run, making the site vulnerable to XSS attacks."
      });
    }
    
    // Check for unsafe-eval
    if ((directives['script-src'] && directives['script-src'].includes("'unsafe-eval'")) ||
        (!directives['script-src'] && directives['default-src'] && directives['default-src'].includes("'unsafe-eval'"))) {
      results.push({
        type: 'unsafe_csp_directive',
        description: "CSP allows 'unsafe-eval' which permits potentially dangerous code evaluation.",
        recommendation: "Remove 'unsafe-eval' from script-src and refactor code to avoid eval().",
        severity: 'medium',
        evidence: cspHeader,
        details: "'unsafe-eval' allows the use of eval() and similar functions, which can lead to XSS vulnerabilities."
      });
    }
    
    // Check for wildcards in sources
    if ((directives['script-src'] && directives['script-src'].includes('*')) ||
        (!directives['script-src'] && directives['default-src'] && directives['default-src'].includes('*'))) {
      results.push({
        type: 'weak_csp_directive',
        description: 'CSP uses wildcards (*) which weakens protection by allowing scripts from any subdomain.',
        recommendation: 'Specify exact domains instead of using wildcards in script-src directive.',
        severity: 'medium',
        evidence: cspHeader,
        details: 'Using wildcards in CSP directives reduces the effectiveness of the policy.'
      });
    }
    
    // Check if report-uri or report-to is set
    if (!directives['report-uri'] && !directives['report-to']) {
      results.push({
        type: 'missing_csp_reporting',
        description: 'CSP reporting is not configured.',
        recommendation: 'Add report-uri or report-to directive to collect CSP violation reports.',
        severity: 'low',
        evidence: cspHeader,
        details: 'CSP reporting helps detect potential attacks and policy configuration issues.'
      });
    }
    
    // Check if frame-ancestors is set (clickjacking protection)
    if (!directives['frame-ancestors']) {
      results.push({
        type: 'missing_frame_ancestors',
        description: 'CSP frame-ancestors directive is missing.',
        recommendation: "Add frame-ancestors directive (e.g., 'frame-ancestors 'none'') to prevent clickjacking.",
        severity: 'low',
        evidence: cspHeader,
        details: 'The frame-ancestors directive restricts which domains can embed your site in an iframe.'
      });
    }
    
    return results;
  }
  
  /**
   * Parse CSP header into directives
   */
  function parseCSP(cspHeader) {
    const directives = {};
    const parts = cspHeader.split(';').map(p => p.trim());
    
    for (const part of parts) {
      if (!part) continue;
      
      const [directive, ...values] = part.split(/\s+/);
      directives[directive.toLowerCase()] = values;
    }
    
    return directives;
  }
  
  module.exports = { scan };