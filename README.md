# VScanner

> **Geek-Style Vulnerability Scanner** - Cross-Platform Security Testing Tool

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-green.svg)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![](https://github.com/i0Ek3/VScanner/blob/main/vscanner.jpg)



## 🚀 Overview

VScanner is a **modular vulnerability scanner** with a geek-style CLI interface, designed for security professionals and penetration testers. Built with Python, it features an extensible plugin architecture, real-time progress tracking, and cross-platform compatibility.

### ✨ Key Features

- 🎯 **4 Core Vulnerability Scanners**
  - XSS (Cross-Site Scripting)
  - SQL Injection (Error-based & Boolean-based)
  - HTTP Misconfiguration (Security Headers & Methods)
  - Open Redirect

- 🎨 **Geek-Style Interface**
  - ASCII art banner
  - Animated progress bars
  - Color-coded output (vulnerabilities in red, info in cyan, success in green)
  - Real-time scan status display
  - Formatted vulnerability tables

- 🔧 **Modular Architecture**
  - Plugin-based scanner system
  - Easy to extend with new scanners
  - Abstract base class for consistency
  - Auto-discovery of scanner modules

- 📊 **Multiple Report Formats**
  - JSON (machine-readable)
  - HTML (human-readable with modern styling)
  - Terminal output (color-coded tables)

- 🌍 **Cross-Platform Support**
  - macOS
  - Linux
  - Windows (with colorama for ANSI color support)

---

## 📁 Project Structure

```
VScanner/
├── main.py                 # Entry point with CLI interface
├── core/                   # Core framework
│   ├── __init__.py        # Package initialization
│   ├── base_scanner.py    # Abstract base scanner class
│   ├── config.py          # Configuration (payloads, headers, settings)
│   ├── ui.py              # Geek-style UI components
│   └── reporter.py        # Report generation (JSON/HTML)
├── scanners/              # Scanner modules (plugin-based)
│   ├── __init__.py        # Scanner registry
│   ├── xss_scanner.py     # XSS detection
│   ├── sqli_scanner.py    # SQL injection detection
│   ├── http_scanner.py    # HTTP misconfiguration detection
│   └── redirect_scanner.py # Open redirect detection
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
├── LICENSE               # MIT License
└── README.md             # This file
```

---

## 🛠️ Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Local Installation

```bash
# Clone the repository
git clone git@github.com:i0Ek3/VScanner.git
cd VScanner

# Install dependencies
pip install -r requirements.txt
```

### Docker Installation

```bash
# Build Docker image
docker build -t vscanner:latest .

# Run container
docker run --rm vscanner:latest --help
```

---

## 📖 Usage

### Basic Usage

```bash
# Run all scanners on a target URL
python main.py -u https://example.com?param=value

# Run specific scanner (XSS only)
python main.py -u https://example.com?param=value -s xss

# Generate HTML report
python main.py -u https://example.com -s all -f html -o my_report

# Disable ASCII banner
python main.py -u https://example.com --no-banner
```

### Command-Line Options

```
Required Arguments:
  -u, --url URL              Target URL to scan (must include http/https)

Optional Arguments:
  -s, --scan-type TYPE       Scan type: xss, sqli, http, redirect, all (default: all)
  -o, --output PATH          Output file path without extension (default: scan_report_TIMESTAMP)
  -f, --format FORMAT        Report format: json, html (default: json)
  -t, --timeout SECONDS      HTTP request timeout (default: 10)
  --no-banner                Disable ASCII banner display
  -h, --help                 Show help message
```

### Examples

```bash
# Scan for XSS vulnerabilities
python main.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -s xss

# Full scan with HTML report
python main.py -u "http://testphp.vulnweb.com/" -s all -f html -o full_scan

# HTTP misconfiguration check only
python main.py -u "https://example.com" -s http

# Custom timeout (20 seconds)
python main.py -u "https://slow-site.com" -t 20
```

### Docker Usage

```bash
# Full scan with volume mount for report output
docker run --rm -v $(pwd):/app/reports vscanner:latest \
  -u https://example.com -s all -o reports/scan_report

# XSS scan only
docker run --rm vscanner:latest \
  -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -s xss
```

---

## 🎨 Geek-Style Features

### ASCII Banner
```
 _    ______                                 
| |  / / ___/_________ _____  ____  ___  _____
| | / /\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
| |/ /___/ / /__/ /_/ / / / / / / /  __/ /    
|___//____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                              
  Vulnerability Scanner v2.0.0
  Cross-Platform Security Testing Tool
  Supports: XSS | SQLi | HTTP Misconfig | Open Redirect
```

### Progress Bars
```
⠋ Running XSS Scanner... ████████████████████ 100% 0:00:05
```

### Color-Coded Output
- 🔵 **Cyan** - Info messages
- 🟢 **Green** - Success messages
- 🟡 **Yellow** - Warnings
- 🔴 **Red** - Errors and vulnerabilities

### Vulnerability Tables
```
┌─────────────────────────┬───────────┬──────────────────┬────────┐
│ Type                    │ Parameter │ Payload/Issue    │ Status │
├─────────────────────────┼───────────┼──────────────────┼────────┤
│ XSS (Reflected)         │ cat       │ <script>alert(1) │ 200    │
└─────────────────────────┴───────────┴──────────────────┴────────┘
```

---

## 🔌 Extending VScanner

### Adding a New Scanner

1. Create a new file in `scanners/` (e.g., `csrf_scanner.py`)
2. Inherit from `BaseScanner` and implement required methods:

```python
from core.base_scanner import BaseScanner
from typing import List, Dict, Any

class CSRFScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "CSRF Scanner"
    
    @property
    def description(self) -> str:
        return "Detects CSRF vulnerabilities"
    
    @property
    def scan_type(self) -> str:
        return "csrf"
    
    def scan(self, target_url: str, params: Dict[str, str] = None) -> List[Dict[str, Any]]:
        # Implement scanning logic
        self.reset()
        # ... your detection logic ...
        return self.vulnerabilities
```

3. Register in `scanners/__init__.py`:

```python
from .csrf_scanner import CSRFScanner

AVAILABLE_SCANNERS = [
    XSSScanner,
    SQLiScanner,
    HTTPScanner,
    RedirectScanner,
    CSRFScanner,  # Add your scanner
]
```

4. Run with `-s csrf` or `-s all`

---

## 📊 Sample Output

### JSON Report
```json
{
    "scan_timestamp": "2025-12-09T19:20:00.123456",
    "target_url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "total_vulnerabilities": 2,
    "vulnerabilities": [
        {
            "type": "XSS (Reflected)",
            "payload": "<script>alert(1)</script>",
            "parameter": "cat",
            "url": "http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "status_code": 200,
            "description": "Unescaped XSS payload reflected in response"
        }
    ]
}
```

### HTML Report
A beautifully styled HTML report with:
- Gradient header with tool branding
- Metadata cards showing scan details
- Vulnerability cards with color-coded severity
- Responsive design for mobile/desktop viewing

---

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for **educational and authorized security testing purposes only**.

- ✅ Only scan targets you **own** or have **explicit written permission** to test
- ❌ Unauthorized scanning is **illegal** and may violate laws (e.g., CFAA in the US)
- 🛡️ The authors are **not responsible** for misuse of this tool

Always obtain proper authorization before conducting security assessments.

---

## 🐛 Limitations

- **GET Requests Only**: Currently only tests GET parameters (extend to POST for full coverage)
- **No Authentication**: Does not support authenticated scans (add `auth` parameter to requests if needed)
- **Basic Payloads**: Uses minimal payloads for demonstration (extend payload lists for comprehensive testing)
- **Educational Purpose**: Not a replacement for professional tools like OWASP ZAP or Burp Suite

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with [Rich](https://github.com/Textualize/rich) for terminal UI
- ASCII art generated with [pyfiglet](https://github.com/pwaller/pyfiglet)
- Cross-platform color support via [colorama](https://github.com/tartley/colorama)

---

## 📧 Contact

For questions, suggestions, or bug reports, please open an issue on GitHub.

**Happy Hacking! 🔐**