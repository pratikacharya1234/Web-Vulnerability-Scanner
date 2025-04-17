/**
 * Security header scanner module
 * Checks for missing or misconfigured security headers
 */
async function scan(page, url) {
    const results = [];
    const { headers } = page;
    
    // Check for missing or insecure headers
    const securityHeaders = {
      'Strict-Transport-Security': {
        missing: 'Missing HSTS header which helps protect against protocol downgrade attacks.',
        recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header.',
        severity: 'medium',
        check: (value) => {
          if (!value) return true;
          // Check if max-age is too short (less than 6 months)
          const maxAgeMatch = value.match(/max-age=(\d+)/);
          if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 15768000) {
            return {
              issue: true,
              details: 'HSTS max-age is too short (less than 6 months)'
            };
          }
          return false;
        }
      },
      'Content-Security-Policy': {
        missing: 'Missing Content-Security-Policy header which helps prevent XSS attacks.',
        recommendation: 'Implement a Content Security Policy with appropriate directives.',
        severity: 'medium',
        check: (value) => {
          if (!value) return true;
          // Check for unsafe CSP directives
          if (value.includes("unsafe-inline") || value.includes("unsafe-eval")) {
            return {
              issue: true,
              details: 'CSP contains unsafe directives (unsafe-inline or unsafe-eval)'
            };
          }
          return false;
        }
      },
      'X-Content-Type-Options': {
        missing: 'Missing X-Content-Type-Options header which prevents MIME type sniffing.',
        recommendation: 'Add "X-Content-Type-Options: nosniff" header.',
        severity: 'medium',
        check: (value) => {
          if (!value) return true;
          if (value !== 'nosniff') {
            return {
              issue: true,
              details: 'X-Content-Type-Options should be set to "nosniff"'
            };
          }
          return false;
        }
      },
      'X-Frame-Options': {
        missing: 'Missing X-Frame-Options header which prevents clickjacking attacks.',
        recommendation: 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header.',
        severity: 'medium',
        check: (value) => {
          if (!value) return true;
          if (value !== 'DENY' && value !== 'SAMEORIGIN') {
            return {
              issue: true,
              details: 'X-Frame-Options should be set to "DENY" or "SAMEORIGIN"'
            };
          }
          return false;
        }
      },
      'X-XSS-Protection': {
        missing: 'Missing X-XSS-Protection header which enables browser XSS filtering.',
        recommendation: 'Add "X-XSS-Protection: 1; mode=block" header.',
        severity: 'low',
        check: (value) => {
          if (!value) return true;
          if (value !== '1; mode=block' && value !== '1') {
            return {
              issue: true,
              details: 'X-XSS-Protection should be set to "1; mode=block"'
            };
          }
          return false;
        }
      },
      'Referrer-Policy': {
        missing: 'Missing Referrer-Policy header which controls how much referrer information is included.',
        recommendation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" header.',
        severity: 'low',
        check: (value) => {
          if (!value) return true;
          // Check for unsafe referrer policies
          const unsafePolicies = ['unsafe-url', 'no-referrer-when-downgrade', ''];
          if (unsafePolicies.includes(value)) {
            return {
              issue: true,
              details: 'Referrer-Policy uses a potentially unsafe value'
            };
          }
          return false;
        }
      },
      'Permissions-Policy': {
        missing: 'Missing Permissions-Policy header which controls browser features.',
        recommendation: 'Consider adding a Permissions-Policy header to restrict access to sensitive browser features.',
        severity: 'low',
        check: (value) => !value
      },
      'Cache-Control': {
        missing: 'Missing Cache-Control header which controls browser caching.',
        recommendation: 'Add "Cache-Control: no-store, max-age=0" header for sensitive pages.',
        severity: 'low',
        check: (value) => {
          // Only check for pages that might be sensitive
          const sensitiveUrlPatterns = [/login/, /admin/, /account/, /profile/, /settings/, /password/];
          const isSensitive = sensitiveUrlPatterns.some(pattern => pattern.test(url));
          
          if (isSensitive) {
            if (!value) return true;
            if (!value.includes('no-store') && !value.includes('private')) {
              return {
                issue: true,
                details: 'Sensitive page should use "no-store" or "private" Cache-Control directive'
              };
            }
          }
          return false;
        }
      }
    };
    
    // Check each security header
    Object.entries(securityHeaders).forEach(([header, info]) => {
      const headerLower = header.toLowerCase();
      const foundHeader = Object.keys(headers).find(h => h.toLowerCase() === headerLower);
      const headerValue = foundHeader ? headers[foundHeader] : null;
      
      const checkResult = info.check(headerValue);
      
      if (checkResult === true) {
        // Header is missing
        results.push({
          type: 'missing_security_header',
          header,
          description: info.missing,
          recommendation: info.recommendation,
          severity: info.severity,
          evidence: `Header not found in response`
        });
      } else if (checkResult && checkResult.issue) {
        // Header has issues
        results.push({
          type: 'misconfigured_security_header',
          header,
          description: `${header} header is present but has issues: ${checkResult.details}`,
          recommendation: info.recommendation,
          severity: info.severity,
          evidence: `${header}: ${headerValue}`
        });
      }
    });
    
    // Check for Server header revealing version info
    const serverHeader = Object.keys(headers).find(h => h.toLowerCase() === 'server');
    if (serverHeader) {
      const serverValue = headers[serverHeader];
      const versionRegex = /[0-9]+\.[0-9]+(?:\.[0-9]+)*/;
      
      if (versionRegex.test(serverValue)) {
        results.push({
          type: 'information_disclosure',
          header: 'Server',
          description: 'Server header reveals version information which can help attackers identify vulnerabilities.',
          recommendation: 'Configure the server to remove version information from the Server header.',
          severity: 'low',
          evidence: `Server: ${serverValue}`
        });
      }
    }
    
    // Check for insecure cookies
    const cookieHeader = headers['set-cookie'] || [];
    const cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
    
    cookies.forEach(cookie => {
      if (!cookie) return;
      
      if (!cookie.includes('HttpOnly')) {
        results.push({
          type: 'insecure_cookie',
          description: 'Cookie missing HttpOnly flag which helps mitigate XSS attacks.',
          recommendation: 'Add HttpOnly flag to cookies containing sensitive information.',
          severity: 'medium',
          evidence: cookie
        });
      }
      
      if (!cookie.includes('Secure') && url.startsWith('https://')) {
        results.push({
          type: 'insecure_cookie',
          description: 'Cookie missing Secure flag which ensures cookies are only sent over HTTPS.',
          recommendation: 'Add Secure flag to all cookies when site is served over HTTPS.',
          severity: 'medium',
          evidence: cookie
        });
      }
      
      if (!cookie.includes('SameSite')) {
        results.push({
          type: 'insecure_cookie',
          description: 'Cookie missing SameSite attribute which helps prevent CSRF attacks.',
          recommendation: 'Add "SameSite=Strict" or "SameSite=Lax" attribute to cookies.',
          severity: 'low',
          evidence: cookie
        });
      }
    });
    
    return results;
  }
  
  module.exports = { scan };