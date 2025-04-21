const fs = require('fs');
const path = require('path');

function generateMarkdown(results) {
  const { target, summary, vulnerabilities } = results;
  const timestamp = new Date().toLocaleString();

  let md = `# 🛡️ Web Vulnerability Scan Report

**Target:** ${target}  
**Scan Date:** ${timestamp}

---

## 📊 Summary
- 🔴 **High:** ${summary.high || 0}
- 🟠 **Medium:** ${summary.medium || 0}
- 🔵 **Low:** ${summary.low || 0}
- ⚪ **Info:** ${summary.info || 0}

---

## ⚠️ Vulnerabilities
`;

  // Group by type
  const grouped = {};
  vulnerabilities.forEach((v) => {
    if (!grouped[v.type]) grouped[v.type] = [];
    grouped[v.type].push(v);
  });

  let count = 1;
  for (const [type, list] of Object.entries(grouped)) {
    md += `### 🔹 ${type.toUpperCase()}\n\n`;

    list.forEach((v) => {
      md += `#### ${count++}. ${v.severity.toUpperCase()} – ${v.url}\n`;
      md += `- **Risk Level:** ${v.riskLevel || v.severity || 'Low'}\n`;
      md += `- **Description:** ${v.description}\n`;
      md += `- **Recommendation:** ${v.recommendation || v.remediation || 'N/A'}\n`;
      md += `- **Evidence:**\n\`\`\`\n${v.evidence || 'N/A'}\n\`\`\`\n\n`;
    });

    md += `---\n`;
  }

  return md;
}

function saveMarkdownReport(filePath, results) {
  const content = generateMarkdown(results);
  fs.writeFileSync(path.resolve(filePath), content, 'utf-8');
  console.log(`📄 Markdown report saved at: ${filePath}`);
}

module.exports = {
  generateMarkdown,
  saveMarkdownReport
};
