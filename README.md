# CachePoisonDetector (CPD-SEC)

[![PyPI version](https://badge.fury.io/py/cpd-sec.svg)](https://badge.fury.io/py/cpd-sec)
[![Python Versions](https://img.shields.io/pypi/pyversions/cpd-sec.svg)](https://pypi.org/project/cpd-sec/)
[![CI](https://github.com/kankburhan/cpd/workflows/CI/badge.svg)](https://github.com/kankburhan/cpd/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A high-concurrency CLI tool for detecting web cache poisoning vulnerabilities.

## Overview
CPD-SEC is a security tool designed to identify vulnerabilities in web caching systems that allow cache poisoning attacks.

## Installation

### Using Pip (Recommended)
You can install CPD-SEC directly from PyPI:
```bash
pip install cpd-sec
```

### From Source
1.  Clone the repository:
    ```bash
    git clone https://github.com/kankburhan/cpd.git
    cd cpd
    ```

2.  Install dependencies using Poetry:
    ```bash
    poetry install
    ```
    *Alternatively, calculate dependencies to requirements.txt and use pip:*
    ```bash
    pip install .
    ```

## Usage

CPD-SEC supports multiple input methods and extensive configuration options.

### 1. Basic Scan (`--url`)
Scan a single target URL.

```bash
# Installed via pip
cpd-sec scan --url https://example.com

# Using poetry
poetry run cpd-sec scan --url https://example.com
```

### 2. Pipeline Mode (Stdin)
Pipe URLs from other tools (like `waybackurls`, `gau`, `subfinder`, or `cat`) directly into CPD-SEC. This is ideal for mass scanning.

```bash
# Scan URLs found by waybackurls
waybackurls target.com | cpd-sec scan

# Scan URLs from a file using cat
cat urls.txt | cpd-sec scan --concurrency 20
```

### 3. File Input (`--file`)
Read URLs from a text file (one URL per line).

```bash
cpd-sec scan --file urls.txt
```

### 4. Raw Request Scan (`--request-file`)
Scan using a raw HTTP request definition (e.g., copied from Burp Suite).

```bash
# Save your request to a file (e.g. request.txt)
cpd-sec scan --request-file request.txt
```

**Alternative: Direct String (`--raw`)**
*Use with caution due to shell escaping characters.*
```bash
cpd-sec scan --raw "GET /api/foo HTTP/1.1
Host: example.com"
```

### 5. Advanced Options

#### Custom Headers (`--header`)
Add custom headers to every request (e.g., cookies, authorization). You can use this flag multiple times.

```bash
cpd-sec scan -u https://admin.example.com \
    -h "Cookie: session=12345" \
    -h "Authorization: Bearer XYZ"
```

#### Output to File (`--output`)
Save the findings to a JSON or HTML file.

**JSON Output:**
```bash
cpd-sec scan -u https://example.com --output results.json
```

**HTML Report (NEW!):**
Generate a professional HTML security report with PoC details:
```bash
cpd-sec scan -u https://example.com --output report.html
```

**Auto-Open Report (`--open`):**
Automatically open the HTML report in your browser:
```bash
cpd-sec scan -u https://example.com --output report.html --open
```

HTML reports include:
- 🔬 Evidence section with cache headers and variant URLs
- 🎯 Proof-of-Concept URLs ready for manual verification
- 📋 Copy-paste curl commands with malicious headers
- ⚠️ Reflected content sections showing where payloads appear

#### Concurrency (`--concurrency`)
Control the number of simultaneous requests (default: 50).

```bash
cpd-sec scan -f targets.txt --concurrency 100
```

#### Verbosity (`--verbose`, `--quiet`)
Control output levels.

```bash
cpd-sec scan -u https://example.com -v  # Debug logging
cpd-sec scan -u https://example.com -q  # Only show findings
```

### 5. Utilities

#### Validate Finding (`validate`)
Manually verify a vulnerability claim step-by-step.

```bash
cpd-sec validate --url https://target.com --header "X-Forwarded-Host: evil.com"
```

#### Update Tool (`update`)
Check for and install the latest version of CPD-SEC.

```bash
cpd-sec update
```

## Features
- **Auto Update Check**: Automatically checks for new versions on run. ![Auto Update](https://img.shields.io/badge/Auto%20Update-Enabled-brightgreen)
- **High Concurrency**: Built with `asyncio` and `aiohttp` for speed.
- **Smart Baseline**: Establishes a stable baseline to reduce false positives.
- **HTML Security Reports**: Professional reports with PoC URLs, curl commands, and evidence details.
- **Advanced Poisoning Detection**:
    - **Header Injection**: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `Fastly-Client-IP`, etc.
    - **Path Normalization**: Exploits backend URL decoding differences (`/foo\bar`).
    - **Query Parameter Normalization**: Detects case-insensitive query param cache keys.
    - **Fat GET**: Sends request bodies with GET requests.
    - **Unkeyed Query Params**: Injects parameters to test cache key inclusion.
    - **Method Override**: Tests `X-HTTP-Method-Override`.
    - **Cache Key Confusion**: Tests URL encoding variants and cache key calculation.
- **Pipeline Ready**: Designed to integrate into your reconnaissance workflow.

## Contributing

We welcome contributions to improve CPD-SEC, especially for new poisoning signatures and false positive reductions.

### Reporting False Positives
If you encounter a false positive (a reported vulnerability that is benign), please open an Issue with:
1.  **Replication Output**: The output of the `validate` command:
    ```bash
    cpd-sec validate --url <TARGET_URL> --header "KEY: VALUE"
    ```
2.  **Context**: Why you believe it is benign (e.g., "The server normalizes the path but returns the same content").

### Contributing Code
1.  **Fork** the repository.
2.  **Clone** your fork locally.
3.  **Install** dependencies: `poetry install`.
4.  **Create a Branch** for your feature/fix.
5.  **Add/Modify Signatures** in `cpd/logic/poison.py`.
6.  **Add Tests** in `tests/` to verify your changes.
7.  **Submit a Pull Request**!

## Support & Donations

If CPD-SEC helped you find vulnerabilities and improve security, consider supporting its development!

**💳 PayPal:**  
[paypal.me/kankburhan](https://www.paypal.com/paypalme/kankburhan)

**💰 Crypto (USDC):**  
```
0x4618393bf4ddc50eb3e75df849b46aca0d0f8e3c
```

Your support helps maintain and improve this open-source security tool. Thank you! 🙏

## License

MIT License - see LICENSE file for details.

