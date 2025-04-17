const fs = require('fs');
const path = require('path');

function generateMarkdown(results) {
  const { target, summary, vulnerabilities } = results;
  let md = `# Web Vulnerability Scan Report

**Target:** ${target}  
**Scan Date:** ${new Date().toLocaleString()}

## 🔍 Summary
- High: ${summary.high}
- Medium: ${summary.medium}
- Low: ${summary.low}
- Info: ${summary.info}

---

## ⚠️ Vulnerabilities\n`;

  vulnerabilities.forEach((v, i) => {
    md += `### ${i + 1}. [${v.type.toUpperCase()}] (${v.severity})
**URL:** ${v.url}  
**Description:** ${v.description}  
**Recommendation:** ${v.recommendation || v.remediation || 'N/A'}  
**Evidence:**\n\`\`\`\n${v.evidence || 'N/A'}\n\`\`\`\n\n`;
  });

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
