# CachePoisonDetector (CPD)

A high-concurrency CLI tool for detecting web cache poisoning vulnerabilities.

## Overview
CPD is a security tool designed to identify vulnerabilities in web caching systems that allow cache poisoning attacks.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-repo/cpd.git
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

CPD supports multiple input methods and extensive configuration options.

### 1. Basic Scan (`--url`)
Scan a single target URL.

```bash
# Using poetry
poetry run cpd scan --url https://example.com

# As an installed package
cpd scan -u https://example.com
```

### 2. Pipeline Mode (Stdin)
Pipe URLs from other tools (like `waybackurls`, `gau`, `subfinder`, or `cat`) directly into CPD. This is ideal for mass scanning.

```bash
# Scan URLs found by waybackurls
waybackurls target.com | cpd scan

# Scan URLs from a file using cat
cat urls.txt | cpd scan --concurrency 20
```

### 3. File Input (`--file`)
Read URLs from a text file (one URL per line).

```bash
cpd scan --file urls.txt
```

### 4. Advanced Options

#### Custom Headers (`--header`)
Add custom headers to every request (e.g., cookies, authorization). You can use this flag multiple times.

```bash
cpd scan -u https://admin.example.com \
    -h "Cookie: session=12345" \
    -h "Authorization: Bearer XYZ"
```

#### Output to File (`--output`)
Save the findings to a JSON file.

```bash
cpd scan -u https://example.com --output results.json
```

#### Concurrency (`--concurrency`)
Control the number of simultaneous requests (default: 50).

```bash
cpd scan -f targets.txt --concurrency 100
```

#### Verbosity (`--verbose`, `--quiet`)
Control output levels.

```bash
cpd scan -u https://example.com -v  # Debug logging
cpd scan -u https://example.com -q  # Only show findings
```

## Features
- **High Concurrency**: Built with `asyncio` and `aiohttp` for speed.
- **Smart Baseline**: Establishes a stable baseline to reduce false positives.
- **Advanced Poisoning**:
    - **Header Injection**: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `Fastly-Client-IP`, etc.
    - **Path Normalization**: Exploits backend URL decoding differences (`/foo\bar`).
    - **Fat GET**: Sends request bodies with GET requests.
    - **Unkeyed Query Params**: Injects parameters to test cache key inclusion.
    - **Method Override**: Tests `X-HTTP-Method-Override`.
- **Pipeline Ready**: Designed to integrate into your reconnaissance workflow.
