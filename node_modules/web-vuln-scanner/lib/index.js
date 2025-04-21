const Scanner = require('./scanner');

/**
 * Create and run a web vulnerability scan
 * @param {string} url - The URL to scan
 * @param {Object} options - Scan configuration options
 * @returns {Promise<Object>} - Scan results
 */
async function scan(url, options = {}) {
  const scanner = new Scanner(url, options);
  return scanner.runScan();
}

module.exports = { scan };
