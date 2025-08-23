const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { URL } = require('url');
const path = require('path');
const debug = require('debug')('web-vuln-scanner:dir-traversal');

/**
 * Directory traversal scanner
 */
async function scan(page, url) {
  const results = [];
  const urlObj = new URL(url);
  
  // Skip if no path components or just "/"
  if (urlObj.pathname === "/" || !urlObj.pathname) {
    return results;
  }
  
  // Check if URL path contains segments that could be manipulated
  const pathSegments = urlObj.pathname.split('/').filter(Boolean);
  
  if (pathSegments.length === 0) {
    return results;
  }
  
  // Check for file extensions that might be vulnerable
  const riskyExtensions = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.cfm'];
  const lastSegment = pathSegments[pathSegments.length - 1];
  const extension = path.extname(lastSegment).toLowerCase();
  
  let shouldTest = false;
  
  // Check for risky file extensions
  if (riskyExtensions.includes(extension)) {
    shouldTest = true;
  }
  
  // Check for path parameters that might access files
  const pathParams = urlObj.searchParams;
  const fileParams = ['file', 'path', 'dir', 'directory', 'page', 'doc', 'document', 'include', 'require', 'source', 'template'];
  
  for (const [param, value] of pathParams) {
    if (fileParams.some(fp => param.toLowerCase().includes(fp))) {
      shouldTest = true;
      break;
    }
  }
  
  if (shouldTest) {
    // Attempt some basic tests for directory traversal
    try {
      // Test for directory traversal vulnerability
      const traversalResults = await testDirectoryTraversal(url);
      results.push(...traversalResults);
    } catch (error) {
      debug(`Error testing for directory traversal: ${error.message}`);
    }
  }
  
  return results;
}

/**
 * Test for directory traversal vulnerabilities
 */
async function testDirectoryTraversal(url) {
  const results = [];
  const urlObj = new URL(url);
  
  // Extract filename or last path segment
  const pathSegments = urlObj.pathname.split('/').filter(Boolean);
  let originalParam = '';
  let traversalUrl = '';
  const lastSegment = pathSegments[pathSegments.length - 1];
  
  // Test path-based traversal
  if (lastSegment && lastSegment.includes('.')) {
    // Replace filename with traversal pattern
    const newPath = urlObj.pathname.replace(lastSegment, '..%2F..%2F..%2Fetc%2Fpasswd');
    const testUrl = new URL(newPath, url).toString();
    traversalUrl = testUrl;
  } else {
    // Check for file parameters
    const fileParams = ['file', 'path', 'dir', 'directory', 'page', 'doc', 'document', 'include', 'require', 'source', 'template'];
    
    for (const [param, value] of urlObj.searchParams) {
      if (fileParams.some(fp => param.toLowerCase().includes(fp))) {
        // Clone the URL and modify the parameter
        originalParam = param;
        const newUrl = new URL(url);
        newUrl.searchParams.set(param, '../../../../etc/passwd');
        traversalUrl = newUrl.toString();
        break;
      }
    }
  }
  
  if (traversalUrl) {
    try {
      debug(`Testing directory traversal: ${traversalUrl}`);
      
      const response = await fetch(traversalUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        },
        timeout: 5000,
        redirect: 'follow'
      });
      
      const content = await response.text();
      
      // Check for common patterns in /etc/passwd
      const unixFilePatterns = [
        /root:.*?:0:0:/i,
        /nobody:.*?:99:99:/i,
        /bin:.*?:1:1:/i,
        /daemon:.*?:2:2:/i
      ];
      
      // Check for Windows file patterns
      const windowsFilePatterns = [
        /\[boot loader\]/i,
        /\[operating systems\]/i,
        /windows\\system32/i
      ];
      
      // Check for file content leak
      const isUnixFileLeak = unixFilePatterns.some(pattern => pattern.test(content));
      const isWindowsFileLeak = windowsFilePatterns.some(pattern => pattern.test(content));
      
      if (isUnixFileLeak || isWindowsFileLeak) {
        results.push({
          type: 'directory_traversal',
          description: 'Directory traversal vulnerability detected. The application allows reading files outside the intended directory.',
          recommendation: 'Validate and sanitize all file paths. Use a whitelist of allowed files/directories.',
          severity: 'high',
          evidence: traversalUrl,
          details: 'The application appears to allow access to system files. This could lead to sensitive information disclosure.'
        });
      } else if (response.status === 200 && content.length > 0) {
        // If we got a 200 OK but content doesn't match known patterns, still flag as potential
        results.push({
          type: 'potential_directory_traversal',
          description: 'Potential directory traversal vulnerability. The application accepted the modified path but returned unexpected content.',
          recommendation: 'Validate and sanitize all file paths. Use a whitelist of allowed files/directories.',
          severity: 'medium',
          evidence: traversalUrl,
          details: 'Manual verification recommended to confirm if this is a false positive.'
        });
      }
    } catch (error) {
      debug(`Error testing traversal URL ${traversalUrl}: ${error.message}`);
    }
  } else {
    // If no good test candidates, still provide a recommendation if URL has risky patterns
    if (url.includes('.php') || url.includes('.asp') || url.includes('file=') || url.includes('path=')) {
      results.push({
        type: 'potential_file_inclusion',
        description: 'URL contains patterns that are often associated with file inclusion functionality.',
        recommendation: 'Ensure all file path inputs are properly validated and sanitized.',
        severity: 'low',
        evidence: url,
        details: 'This is a heuristic check based on URL analysis. No active testing was performed.'
      });
    }
  }
  
  return results;
}

module.exports = { scan };
