const net = require('net');
const { URL } = require('url');
const debug = require('debug')('web-vuln-scanner:port');

/**
 * Common open ports and their services
 */
const commonPorts = {
  20: 'FTP data',
  21: 'FTP control',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPC',
  135: 'MSRPC',
  139: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1434: 'MSSQL Monitor',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  8080: 'HTTP Alternate',
  8443: 'HTTPS Alternate'
};

/**
 * Port scanner
 */
async function scan(url) {
  const results = [];
  
  try {
    const { hostname } = new URL(url);
    
    debug(`Scanning common ports for ${hostname}`);
    
    // Only scan common ports to avoid excessive scanning
    const portsToScan = Object.keys(commonPorts).map(Number);
    const scanPromises = portsToScan.map(port => checkPort(hostname, port));
    
    const portResults = await Promise.allSettled(scanPromises);
    
    const openPorts = portResults
      .filter(result => result.status === 'fulfilled' && result.value.open)
      .map(result => result.value);
    
    if (openPorts.length > 0) {
      // Group results by severity
      const highRiskPorts = [21, 23, 139, 445, 3389];
      const mediumRiskPorts = [22, 25, 110, 143, 1433, 3306, 5432];
      
      openPorts.forEach(portInfo => {
        let severity = 'low';
        if (highRiskPorts.includes(portInfo.port)) {
          severity = 'high';
        } else if (mediumRiskPorts.includes(portInfo.port)) {
          severity = 'medium';
        }
        
        results.push({
          type: 'open_port',
          description: `Port ${portInfo.port} (${portInfo.service}) is open.`,
          recommendation: `Restrict access to port ${portInfo.port} if the service is not required.`,
          severity,
          evidence: `Port ${portInfo.port} is accessible`,
          details: 'Open ports increase the attack surface of the server.'
        });
      });
    } else {
      results.push({
        type: 'port_scan_info',
        description: 'No commonly exploitable open ports were detected.',
        recommendation: 'Continue to monitor and restrict access to necessary services only.',
        severity: 'info',
        evidence: 'Scanned common ports'
      });
    }
  } catch (error) {
    debug(`Port scan error: ${error.message}`);
    results.push({
      type: 'port_scan_error',
      description: `Error during port scan: ${error.message}`,
      recommendation: 'Use dedicated tools like Nmap for comprehensive port scanning.',
      severity: 'info',
      evidence: error.message
    });
  }
  
  return results;
}

/**
 * Check if a port is open
 */
async function checkPort(hostname, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const service = commonPorts[port] || 'Unknown';
    
    // Short timeout for quicker scans
    socket.setTimeout(1500); 
    
    socket.on('connect', () => {
      socket.destroy();
      resolve({ port, open: true, service });
    });
    
    socket.on('error', () => {
      socket.destroy();
      resolve({ port, open: false, service });
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, open: false, service });
    });
    
    try {
      socket.connect(port, hostname);
    } catch (e) {
      resolve({ port, open: false, service });
    }
  });
}

module.exports = { scan };
