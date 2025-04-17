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
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { background: #fff; padding: 20px; border-bottom: 1px solid #eee; margin-bottom: 20px; }
        h1 { margin-top: 0; }
        .summary-box { display: flex; justify-content: space-between; margin-bottom: 30px; }
        .summary-item { flex: 1; padding: 15px; margin: 0 5px; border-radius: 5px; color: #fff; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .severity { padding: 4px 10px; border-radius: 3px; font-weight: bold; display: inline-block; color: #fff; }
        .evidence { background: #f5f5f5; padding: 10px; font-family: monospace; border: 1px solid #ccc; border-radius: 4px; }
        .remediation { border-left: 4px solid #64b5f6; padding-left: 10px; margin-top: 10px; }
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <h1>Web Vulnerability Scan Report</h1>
          <p><strong>Target:</strong> ${results.target}</p>
          <p><strong>Scan Date:</strong> ${timestamp}</p>
        </header>

        <h2>Summary</h2>
        <div class="summary-box">
          <div class="summary-item" style="background-color: ${severityColor.high}">
            <h3>High</h3><p>${countBySeverity.high}</p>
          </div>
          <div class="summary-item" style="background-color: ${severityColor.medium}">
            <h3>Medium</h3><p>${countBySeverity.medium}</p>
          </div>
          <div class="summary-item" style="background-color: ${severityColor.low}">
            <h3>Low</h3><p>${countBySeverity.low}</p>
          </div>
          <div class="summary-item" style="background-color: ${severityColor.info}">
            <h3>Info</h3><p>${countBySeverity.info}</p>
          </div>
        </div>

        <h2>Vulnerability Details</h2>`;

  const grouped = {};
  results.vulnerabilities.forEach(v => {
    if (!grouped[v.type]) grouped[v.type] = [];
    grouped[v.type].push(v);
  });

  for (const [type, vulns] of Object.entries(grouped)) {
    html += `<h3>${type}</h3><table><thead>
      <tr><th>Severity</th><th>URL</th><th>Description</th><th>Details</th></tr></thead><tbody>`;

    vulns.forEach(v => {
      html += `
        <tr>
          <td><span class="severity" style="background-color: ${severityColor[v.severity] || '#999'}">${v.severity.toUpperCase()}</span></td>
          <td>${v.url}</td>
          <td>${v.description}</td>
          <td>
            <div class="evidence">${escapeHtml(v.evidence || 'N/A')}</div>
            <div class="remediation">
              <strong>Remediation:</strong><br/>
              ${escapeHtml(v.remediation || 'N/A')}
            </div>
          </td>
        </tr>`;
    });

    html += `</tbody></table>`;
  }

  html += `</div></body></html>`;
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

module.exports = {
  generateReport,
  saveReport
};
