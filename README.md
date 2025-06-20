
---

## **Advanced XSS Scanner Tool**

```markdown
#  Advanced Reflected XSS Scanner

An advanced automated Python tool for discovering reflected XSS vulnerabilities in web applications. Performs intelligent recon, input vector discovery, payload fuzzing, and impact detection — with full report generation.

##  Features

- Takes a wildcard domain or base URL as input
- Performs automatic:
  - Subdomain enumeration
  - Input vector detection
  - XSS payload injection
- Analyzes responses for:
  - Reflection
  - Execution
  - CSP bypass attempts
- Screenshots vulnerable endpoints (with Selenium or headless browser)
- Generates a full HTML/JSON report with:
  - Affected URL
  - Parameter
  - Payload
  - Screenshot
  - Execution context

##  Technologies

- Python 3.x
- `requests`
- `beautifulsoup4`
- `selenium` or `playwright`
- `argparse`, `re`
- `aiohttp` (if async)
- `colorama` (optional)

##  Installation

```bash
git clone https://github.com/3bwahab/advanced-xss-scanner.git
cd advanced-xss-scanner
pip install -r requirements.txt```


