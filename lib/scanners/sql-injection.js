/**
 * SQL Injection vulnerability scanner
 */
async function scan(page, url) {
    const results = [];
    const { status, content } = page;
    
    // Get URL parameters for testing
    const urlObj = new URL(url);
    const params = urlObj.searchParams;
    
    // No parameters, no SQL injection test
    if (params.size === 0) {
      return results;
    }
    
    // Check for parameter names that suggest database interaction
    const dataSuggestingNames = ['id', 'user', 'account', 'num', 'item', 'page', 'report', 'file', 'doc', 
                                'key', 'name', 'date', 'category', 'type', 'query', 'search', 'filter', 'where'];
    
    // Error patterns that might indicate SQL injection vulnerability
    const sqlErrorPatterns = [
      /SQL syntax.*?MySQL/i,
      /Warning.*?\Wmysqli?_/i,
      /PostgreSQL.*?ERROR/i,
      /SQLite\/JDBCDriver/i,
      /SQLite\.Exception/i,
      /System\.Data\.SQLite\.SQLiteException/i,
      /Unclosed quotation mark after the character string/i,
      /ODBC SQL Server Driver/i,
      /Microsoft SQL Native Client error/i,
      /Oracle.*?Driver/i,
      /Warning.*?\\W(pg|pgsql)_/i,
      /quoted string not properly terminated/i,
      /syntax error at or near/i
    ];
    
    // Check content for SQL error messages
    const hasSqlErrors = sqlErrorPatterns.some(pattern => pattern.test(content));
    
    // If SQL errors found, that's already a red flag
    if (hasSqlErrors) {
      results.push({
        type: 'sql_error_disclosure',
        description: 'SQL error messages are being displayed to users, which can help attackers craft SQL injection attacks.',
        recommendation: 'Configure database and application to hide detailed error messages from users. Use custom error pages.',
        severity: 'high',
        evidence: 'SQL error pattern detected in response',
        details: 'Database error messages can reveal table names, column names, and query structures.'
      });
    }
    
    // Check if parameters might be used in database queries
    for (const [param, value] of params.entries()) {
      const paramLower = param.toLowerCase();
      
      // Check if parameter name suggests database interaction
      if (dataSuggestingNames.some(name => paramLower.includes(name))) {
        // Higher severity if SQL errors were detected
        const severity = hasSqlErrors ? 'high' : 'medium';
        
        results.push({
          type: 'potential_sql_injection',
          description: `Parameter "${param}" has a name suggesting database interaction and might be vulnerable to SQL injection.`,
          recommendation: 'Implement prepared statements or parameterized queries. Validate and sanitize all inputs.',
          severity,
          evidence: `Parameter: ${param}, Current value: ${value}`,
          details: 'This is a heuristic detection. Manual verification with tools like sqlmap is recommended.'
        });
      }
      
      // Check for numeric IDs
      if (/^id$/i.test(param) && /^\d+$/.test(value)) {
        results.push({
          type: 'numeric_id_parameter',
          description: 'Page uses numeric ID parameters which are common SQL injection targets.',
          recommendation: 'Ensure proper input validation and use parameterized queries for all database operations.',
          severity: 'low',
          evidence: `Parameter: ${param}=${value}`,
          details: 'Consider using non-sequential IDs or additional access controls to prevent parameter tampering.'
        });
      }
    }
    
    return results;
  }
  
  module.exports = { scan };
  