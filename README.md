#  Advanced  XSS Scanner

A powerful and modular Python tool built to automate the discovery and exploitation of reflected XSS (Cross-Site Scripting) vulnerabilities across large web applications or entire subdomain environments. Designed for penetration testers, bug bounty hunters, and red teams seeking high-confidence, high-impact XSS detection with automated reporting and payload evaluation.

---

##  Key Features

 Wildcard domain input — scan all subdomains  
 Intelligent input vector discovery — forms, parameters, URL rewrites  
 Advanced payload fuzzing with execution tracking  
 CSP bypass detection and DOM sink tracing  
 Headless browser-based reflection validation (Selenium/Playwright)  
 Screenshot capture of successful payload execution  
 Automated HTML/JSON vulnerability reporting  
 Modular codebase for easy extension and integration

---

##  How It Works

1. **Target Acquisition**
   - Accepts a wildcard domain or base URL
   - Performs subdomain enumeration and link crawling

2. **Input Vector Discovery**
   - Identifies GET/POST parameters
   - Parses forms, search bars, and dynamic query parameters

3. **Payload Injection**
   - Injects payloads from a customizable list
   - Includes classic, evasive, and CSP-bypass payloads

4. **Response Analysis**
   - Checks for reflected payloads and XSS sinks
   - Detects inline script execution and event-based triggers

5. **Browser-based Validation**
   - Uses headless browsers (Selenium or Playwright)
   - Confirms payload execution and captures screenshots

6. **Reporting**
   - Outputs detailed report per endpoint:
     - Vulnerable URL
     - Payload used
     - Reflection point
     - Execution status
     - Screenshot path
     - Impact level

---

##  Installation

```bash
git clone https://github.com/3bwahab/advanced-xss-scanner.git
cd advanced-xss-scanner
pip install -r requirements.txt
python3 v30.py example.com
