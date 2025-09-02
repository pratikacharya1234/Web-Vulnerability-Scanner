# Contributing to Web Vulnerability Scanner

Thank you for considering contributing to Web Vulnerability Scanner! 🚀 We're excited to collaborate and improve the security landscape together.

## Code of Conduct

We expect all contributors to be respectful, inclusive, and constructive. All contributions, feedback, and ideas are welcome. Please treat everyone with respect and help us maintain a positive community environment.

## Ways to Contribute

*  **Fix bugs** — Found something broken? Let's squash it!
*  **Add new scanners** — RCE, IDOR, SSRF, Misconfigurations, etc.
*  **Optimize performance** — Make scanning faster and smarter.
*  **Add tests** — Unit, integration, regression – everything helps.
*  **Improve CLI UX** — Make the terminal interface better for devs.
*  **Add report formats** — PDF, CSV, or integrations like Slack/GitHub.
*  **Improve documentation** — Clarity = Power.
*  **CI/CD Enhancements** — Add GitHub Actions, test runners, or release bots.

## Getting Started

### Prerequisites

- Node.js (latest LTS version recommended)
- npm or yarn
- Git

### Setup

```bash
git clone https://github.com/pratikacharya1234/Web-Vulnerability-Scanner.git
cd Web-Vulnerability-Scanner
npm install
```

### Run a Scan

```bash
node bin/cli.js https://example.com --format console
```

## Project Structure

```
bin/cli.js                # CLI entry
lib/
├── scanner.js            # Core scan engine
├── crawler.js            # Smart URL crawler
├── index.js              # Entry point
├── reporters/            # HTML/Markdown reports
└── scanners/             # XSS, SQLi, CSRF, RCE, IDOR, etc.
```

## Development Workflow

1. **Fork the repository** on GitHub.
2. **Clone your fork** to your local machine.
3. **Create a new branch** for your feature or bugfix (`git checkout -b feature/your-feature-name`).
4. **Make your changes** and commit them with meaningful messages.
5. **Run tests** to ensure your changes don't break existing functionality.
6. **Push your branch** to your fork on GitHub.
7. **Open a pull request** against the main repository.

## Coding Standards

- Use ESLint and Prettier with the project's configuration.
- Write meaningful commit messages.
- Document new functions, classes, and modules.
- Include tests for new functionality.
- Keep code modular and reusable.

## Pull Request Process

1. Update the README.md or documentation with details of changes if applicable.
2. Include tests for new functionality.
3. Update the version number in relevant files following [Semantic Versioning](https://semver.org/).
4. Your pull request will be reviewed by maintainers, who may request changes.
5. Once approved, your pull request will be merged.

## Pull Request Checklist

* Clean, modular code
* Includes tests or examples (if relevant)
* Adds meaningful commit messages
* Updates README or docs if required
* Doesn't break backward compatibility

## Adding New Scanners

When adding a new vulnerability scanner:

1. Create a new file in the `lib/scanners/` directory.
2. Follow the existing pattern for scanner implementation.
3. Ensure your scanner has proper documentation.
4. Include test cases that demonstrate both positive and negative detection.
5. Update relevant documentation to reflect the new scanner capabilities.

## Testing

We use Jest for testing. Run tests with:

```bash
npm test
```

Write tests for new functionality and ensure all tests pass before submitting a pull request.

## Bug Reports and Feature Requests

Please use GitHub Issues to report bugs or request features. When reporting bugs:

1. Use a clear and descriptive title.
2. Describe the exact steps to reproduce the bug.
3. Provide specific examples, like a URL that triggers the issue.
4. Describe the behavior you observed and what you expected to see.
5. Include screenshots if applicable.

## Questions?

Open an issue or start a discussion. We're happy to brainstorm or help!

Let's build a safer web together 