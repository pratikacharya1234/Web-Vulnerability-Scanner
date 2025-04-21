const fs = require('fs');
const path = require('path');

function generateReport(results) {
  const timestamp = new Date().toLocaleString();
  const severityColor = {
    high: '#ea5545',
    medium: '#f46a9b',
    low: '#87bc45',
    info: '#64b5f6'
  };

  const countBySeverity = {
    high: results.summary.high || 0,
    medium: results.summary.medium || 0,
    low: results.summary.low || 0,
    info: results.summary.info || 0
  };

  let html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Web Vulnerability Scan Report</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #333; }
        header { background: #fff; padding: 20px; margin-bottom: 20px; }
        h1, h2, h3 { margin-top: 0; }
        .summary-box { display: flex; gap: 10px; margin-bottom: 30px; }
        .summary-item { flex: 1; padding: 15px; border-radius: 5px; color: #fff; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .severity { font-weight: bold; padding: 4px 10px; border-radius: 3px; color: #fff; }
        .evidence { background: #f1f1f1; padding: 10px; border-radius: 4px; font-family: monospace; }
        .remediation { border-left: 4px solid #64b5f6; padding-left: 10px; margin-top: 10px; }
      </style>
    </head>
    <body>
      <header>
        <h1>Web Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> ${results.target}</p>
        <p><strong>Scan Date:</strong> ${timestamp}</p>
      </header>

      <h2>Summary</h2>
      <div class="summary-box">
        ${['high', 'medium', 'low', 'info'].map(sev => `
          <div class="summary-item" style="background-color: ${severityColor[sev]}">
            <h3>${sev.charAt(0).toUpperCase() + sev.slice(1)}</h3>
            <p>${countBySeverity[sev]}</p>
          </div>
        `).join('')}
      </div>

      <h2>Vulnerability Details</h2>`;

  const grouped = {};
  results.vulnerabilities.forEach(v => {
    if (!grouped[v.type]) grouped[v.type] = [];
    grouped[v.type].push(v);
  });

  for (const [type, vulns] of Object.entries(grouped)) {
    html += `<h3>${type}</h3>
      <table>
        <thead><tr><th>Severity</th><th>Risk Level</th><th>URL</th><th>Description</th><th>Details</th></tr></thead>
        <tbody>`;
    vulns.forEach(v => {
      html += `
        <tr>
          <td><span class="severity" style="background-color: ${severityColor[v.severity] || '#888'}">${v.severity.toUpperCase()}</span></td>
          <td>${v.riskLevel || 'Low'}</td>
          <td>${v.url}</td>
          <td>${v.description}</td>
          <td>
            ${v.evidence ? `<div class="evidence">${escapeHtml(v.evidence)}</div>` : ''}
            <div class="remediation"><strong>Remediation:</strong><br/>${escapeHtml(v.remediation || 'N/A')}</div>
          </td>
        </tr>`;
    });
    html += `</tbody></table>`;
  }

  html += `</body></html>`;
  return html;
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, match => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
  })[match]);
}

function saveReport(filePath, results) {
  const report = generateReport(results);
  fs.writeFileSync(path.resolve(filePath), report, 'utf-8');
  console.log(`✅ HTML report saved at: ${filePath}`);
}

module.exports = { generateReport, saveReport };
