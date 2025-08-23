const tls = require('tls');
const { promisify } = require('util');
const { URL } = require('url');
const dns = require('dns');
const debug = require('debug')('web-vuln-scanner:ssl');

/**
 * SSL/TLS security scanner
 */
async function scan(url) {
  const results = [];
  
  if (!url.startsWith('https://')) {
    results.push({
      type: 'insecure_protocol',
      description: 'Website is not using HTTPS, which leaves data transmission unencrypted.',
      recommendation: 'Implement HTTPS using a valid SSL/TLS certificate.',
      severity: 'high',
      evidence: url
    });
    return results;
  }
  
  try {
    const { hostname, port: urlPort } = new URL(url);
    const port = urlPort || 443;
    
    // Check for certificate and TLS configuration
    const certInfo = await checkCertificate(hostname, port);
    
    // Certificate validity
    const now = new Date();
    if (now > certInfo.validTo) {
      results.push({
        type: 'expired_certificate',
        description: 'SSL certificate has expired.',
        recommendation: 'Renew the SSL certificate immediately.',
        severity: 'high',
        evidence: `Certificate expired on ${certInfo.validTo.toISOString()}`
      });
    } else if (now > new Date(certInfo.validTo.getTime() - 30 * 24 * 60 * 60 * 1000)) {
      // Expires in less than 30 days
      results.push({
        type: 'expiring_certificate',
        description: 'SSL certificate will expire in less than 30 days.',
        recommendation: 'Renew the SSL certificate before it expires.',
        severity: 'medium',
        evidence: `Certificate expires on ${certInfo.validTo.toISOString()}`
      });
    }
    
    // Self-signed certificate
    if (certInfo.issuer.CN === certInfo.subject.CN) {
      results.push({
        type: 'self_signed_certificate',
        description: 'Website is using a self-signed certificate which browsers will warn about.',
        recommendation: 'Use a certificate from a trusted Certificate Authority.',
        severity: 'high',
        evidence: `Certificate issuer: ${certInfo.issuer.CN}`
      });
    }
    
    // TLS version
    if (certInfo.protocol === 'TLSv1' || certInfo.protocol === 'TLSv1.1') {
      results.push({
        type: 'obsolete_tls_version',
        description: `Website is using an obsolete TLS version (${certInfo.protocol}).`,
        recommendation: 'Configure server to use TLS 1.2 or higher and disable older versions.',
        severity: 'high',
        evidence: `Protocol: ${certInfo.protocol}`
      });
    }
    
    // Hostname mismatch
    if (!certInfo.validForHost) {
      results.push({
        type: 'hostname_mismatch',
        description: 'SSL certificate is not valid for the requested hostname.',
        recommendation: 'Obtain a certificate that includes this hostname or use the correct hostname.',
        severity: 'high',
        evidence: `Certificate is for: ${certInfo.subject.CN}, but accessed as: ${hostname}`
      });
    }
    
    // Weak cipher suites
    if (certInfo.cipherSuite && certInfo.cipherSuite.includes('RSA')) {
      results.push({
        type: 'weak_cipher_suite',
        description: 'The server is configured to use RSA key exchange which is less secure than ECDHE.',
        recommendation: 'Configure server to prefer ECDHE based cipher suites for perfect forward secrecy.',
        severity: 'medium',
        evidence: `Cipher suite: ${certInfo.cipherSuite}`
      });
    }
    
    // If all checks passed, add an info result
    if (results.length === 0) {
      results.push({
        type: 'ssl_configuration_ok',
        description: 'SSL/TLS configuration appears to be properly configured.',
        recommendation: 'Continue to monitor and maintain regular certificate renewal processes.',
        severity: 'info',
        evidence: `Certificate valid until ${certInfo.validTo.toISOString()}`
      });
    }
  } catch (error) {
    debug(`SSL scan error: ${error.message}`);
    results.push({
      type: 'ssl_scan_error',
      description: `Error checking SSL configuration: ${error.message}`,
      recommendation: 'Check server SSL configuration manually using specialized tools.',
      severity: 'info',
      evidence: error.message
    });
  }
  
  return results;
}

/**
 * Check certificate and TLS configuration
 */
async function checkCertificate(hostname, port) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port: port,
      rejectUnauthorized: false,
      timeout: 10000
    };
    
    const socket = tls.connect(options);
    
    // Set a connection timeout
    const connectionTimeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('Connection timeout'));
    }, 15000);
    
    socket.once('secureConnect', () => {
      clearTimeout(connectionTimeout);
      
      try {
        const cert = socket.getPeerCertificate(true);
        
        // Check if certificate is empty
        if (!cert || Object.keys(cert).length === 0) {
          socket.end();
          return reject(new Error('Unable to get certificate information'));
        }
        
        const protocol = socket.getProtocol() || 'Unknown';
        const cipherSuite = socket.getCipher() || { name: 'Unknown' };
        const validForHost = socket.authorized || false;
        
        socket.end();
        
        resolve({
          subject: cert.subject || { CN: 'Unknown' },
          issuer: cert.issuer || { CN: 'Unknown' },
          validFrom: cert.valid_from ? new Date(cert.valid_from) : new Date(),
          validTo: cert.valid_to ? new Date(cert.valid_to) : new Date(),
          protocol,
          cipherSuite: cipherSuite.name,
          validForHost
        });
      } catch (error) {
        socket.end();
        clearTimeout(connectionTimeout);
        reject(error);
      }
    });
    
    socket.on('error', (error) => {
      clearTimeout(connectionTimeout);
      socket.destroy();
      reject(error);
    });
    
    socket.on('timeout', () => {
      clearTimeout(connectionTimeout);
      socket.destroy();
      reject(new Error('Socket timeout'));
    });
  });
}

module.exports = { scan };