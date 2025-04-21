/**
 * CSRF vulnerability scanner
 */
async function scan(page, url) {
    const results = [];
    const { dom, content } = page;
    
    if (!dom) return results;
    
    // Get all forms
    const forms = dom.window.document.querySelectorAll('form');
    
    if (forms.length === 0) {
      return results;
    }
    
    let hasVulnerableForm = false;
    const formDetails = [];
    
    forms.forEach((form, index) => {
      const method = (form.getAttribute('method') || 'GET').toUpperCase();
      const action = form.getAttribute('action') || '';
      
      // Skip GET forms as they're typically not vulnerable to CSRF
      if (method === 'GET') {
        return;
      }
      
      // Check for CSRF token in form
      const inputs = form.querySelectorAll('input');
      let hasCSRFToken = false;
      let tokenFieldName = '';
      
      const csrfTokenPatterns = [
        /csrf/i,
        /token/i,
        /nonce/i,
        /_token/i,
        /authenticity_token/i
      ];
      
      inputs.forEach(input => {
        const name = input.getAttribute('name') || '';
        const value = input.getAttribute('value') || '';
        
        if (csrfTokenPatterns.some(pattern => pattern.test(name)) && value) {
          hasCSRFToken = true;
          tokenFieldName = name;
        }
      });
      
      if (!hasCSRFToken) {
        hasVulnerableForm = true;
        formDetails.push(`Form ${index + 1} (method: ${method}, action: ${action})`);
      }
    });
    
    // Also check for same-site cookie attribute
    const cookieHeader = page.headers['set-cookie'] || [];
    const cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
    let hasSameSiteCookies = false;
    
    for (const cookie of cookies) {
      if (cookie && cookie.includes('SameSite=')) {
        hasSameSiteCookies = true;
        break;
      }
    }
    
    // If forms exist but no CSRF protection detected
    if (hasVulnerableForm) {
      results.push({
        type: 'potential_csrf',
        description: 'Form submission without apparent CSRF protection detected.',
        recommendation: 'Implement CSRF tokens for all forms that modify data. Add SameSite=Strict attribute to cookies.',
        severity: hasSameSiteCookies ? 'medium' : 'high', // Lower severity if at least SameSite cookies are used
        evidence: formDetails.join(', '),
        details: 'CSRF vulnerabilities can allow attackers to perform actions on behalf of authenticated users.'
      });
    }
    
    return results;
  }
  
  module.exports = { scan };