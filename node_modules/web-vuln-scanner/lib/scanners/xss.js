/**
 * Cross-Site Scripting (XSS) vulnerability scanner
 */
async function scan(page, url) {
    const results = [];
    const { content, dom } = page;
    
    if (!content) {
      return results;
    }
    
    // Check for reflected input parameters in HTML
    const urlObj = new URL(url);
    const params = urlObj.searchParams;
    
    params.forEach((value, param) => {
        // Skip empty or too short values
      if (!value || value.length < 2) return; 
      
      if (content.includes(value)) {
        // Find where the value appears in content
        const context = findContext(content, value);
        
        // Check if value appears in a risky context
        let severity = 'medium';
        let contextInfo = '';
        
        if (context.inScript) {
          severity = 'high';
          contextInfo = ' Value appears in script context which is high risk.';
        } else if (context.inAttribute) {
          severity = 'high';
          contextInfo = ' Value appears in HTML attribute which is high risk.';
        } else if (context.inComment) {
          severity = 'medium';
          contextInfo = ' Value appears in HTML comment.';
        }
        
        results.push({
          type: 'potential_reflected_xss',
          description: `Parameter "${param}" value is reflected in the page response.${contextInfo}`,
          recommendation: 'Implement proper output encoding based on context (HTML, attribute, JavaScript, CSS) and implement Content Security Policy.',
          severity,
          evidence: `Parameter: ${param}, Value: ${value}`,
          details: 'This is a preliminary check. Manual verification is recommended.'
        });
      }
    });
    
    // If we have a DOM, check for vulnerable patterns
    if (dom) {
      // Check for potentially vulnerable inputs
      const inputs = dom.window.document.querySelectorAll('input');
      
      inputs.forEach(input => {
        const type = input.getAttribute('type');
        const name = input.getAttribute('name');
        
        if (type !== 'hidden' && name) {
          const autocomplete = input.getAttribute('autocomplete');
          const sensitive = ['password', 'email', 'tel', 'cc-number', 'card-number', 'ccnumber'];
          
          if (sensitive.some(s => name.toLowerCase().includes(s)) && (!autocomplete || autocomplete !== 'off')) {
            results.push({
              type: 'unsecured_input',
              description: `Sensitive input field ${name} without autocomplete="off" could potentially leak data.`,
              recommendation: 'Add autocomplete="off" for sensitive inputs and implement proper validation.',
              severity: 'low',
              evidence: input.outerHTML
            });
          }
        }
      });
      
      // Check for javascript: URLs
      const links = dom.window.document.querySelectorAll('a');
      links.forEach(link => {
        const href = link.getAttribute('href');
        if (href && href.toLowerCase().startsWith('javascript:')) {
          results.push({
            type: 'javascript_uri',
            description: 'Link uses javascript: URI which can be a vector for XSS attacks.',
            recommendation: 'Avoid using javascript: URIs. Use event handlers or buttons instead.',
            severity: 'medium',
            evidence: link.outerHTML
          });
        }
      });
      
      // Check for event handlers with inline JavaScript
      const elementsWithEvents = dom.window.document.querySelectorAll('[onclick], [onload], [onmouseover], [onerror]');
      if (elementsWithEvents.length > 0) {
        results.push({
          type: 'inline_event_handlers',
          description: 'Page uses inline event handlers which can be a vector for XSS attacks if user input is not properly sanitized.',
          recommendation: 'Move JavaScript to separate files and avoid inline event handlers. Use addEventListener instead.',
          severity: 'low',
          evidence: `Found ${elementsWithEvents.length} elements with inline event handlers`
        });
      }
      
      // Check for eval(), document.write() and similar dangerous functions
      const scripts = dom.window.document.querySelectorAll('script');
      const dangerousFunctions = ['eval(', 'document.write(', 'innerHTML', 'outerHTML', 'setTimeout(', 'setInterval('];
      
      scripts.forEach(script => {
        const scriptContent = script.textContent;
        if (!scriptContent) return;
        
        for (const func of dangerousFunctions) {
          if (scriptContent.includes(func)) {
            results.push({
              type: 'dangerous_js_function',
              description: `Script uses potentially dangerous function '${func}' which can be a vector for XSS if user input is not properly sanitized.`,
              recommendation: 'Avoid using dangerous functions like eval(), document.write(), innerHTML with user input. Use safer alternatives.',
              severity: 'medium',
              evidence: `Script contains ${func}`
            });
            break; // Only report once per script
          }
        }
      });
    }
    
    return results;
  }
  
  // Helper function to determine context of a string in HTML
  function findContext(html, str) {
    const context = {
      inScript: false,
      inAttribute: false,
      inComment: false
    };
    
    // Find string position in HTML
    const pos = html.indexOf(str);
    if (pos === -1) return context;
    
    // Get substring before our target
    const beforeStr = html.substring(0, pos);
    
    // Check if inside a script tag
    const scriptOpenCount = (beforeStr.match(/<script/gi) || []).length;
    const scriptCloseCount = (beforeStr.match(/<\/script>/gi) || []).length;
    context.inScript = scriptOpenCount > scriptCloseCount;
    
    // Check if inside a comment
    const commentOpenCount = (beforeStr.match(/<!--/g) || []).length;
    const commentCloseCount = (beforeStr.match(/-->/g) || []).length;
    context.inComment = commentOpenCount > commentCloseCount;
    
    // Check if inside an attribute (simplified - doesn't handle all edge cases)
    const lastOpenQuote = Math.max(beforeStr.lastIndexOf('"'), beforeStr.lastIndexOf("'"));
    const lastCloseQuote = Math.max(beforeStr.lastIndexOf('"', lastOpenQuote - 1), 
                                    beforeStr.lastIndexOf("'", lastOpenQuote - 1));
    context.inAttribute = lastOpenQuote > lastCloseQuote;
    
    return context;
  }
  
  module.exports = { scan };