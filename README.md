# DBMS - Database Management & Security Scanning System

Advanced security scanning and vulnerability assessment toolkit with AI-powered analysis.

## Features

### 🔍 Reconnaissance & Scanning
- **Naabu Integration**: Fast port discovery before detailed Nmap scans
- **Service Fingerprinting**: Advanced service detection with version identification
- **Subdomain Filtering**: Automatic filtering of discovered subdomains against input scope
- **URL Resolution**: Intelligent redirect handling and final URL resolution

### 🚀 Directory Brute-forcing (Gobuster)
- **Tor Integration**: Anonymous scanning with automatic identity rotation
- **403 Bypass Techniques**: Multiple bypass methods (headers, path manipulation, HTTP methods)
- **Windows Reserved Names Filtering**: Automatic filtering of invalid paths
- **Baseline Signatures**: False positive reduction through baseline collection
- **Generic Error Detection**: Intelligent error page filtering
- **State Management**: Thread-safe state handling without race conditions

### 🎯 Nuclei Template Generation
- **POC Analysis**: Structured extraction of URLs, paths, methods, parameters, payloads
- **File Prioritization**: Intelligent ranking of POC files by relevance
- **Vulnerability Type Detection**: Automatic classification (RCE, SQLi, XSS, etc.)
- **Strict Validation**: Rejects AI-generated templates with fake authors
- **Official Templates**: Prioritizes projectdiscovery templates
- **AI-Powered Generation**: Creates production-quality templates from POCs

### 🔎 CVE Hunting
- **Multiple Sources**: NVD, DuckDuckGo, PacketStorm, GitHub
- **Result Caching**: Persistent caching of CVE search results
- **Template Validation**: AI-powered template selection and filtering
- **Fake Author Detection**: Filters out templates from topscoder, grok, etc.
- **POC Discovery**: Automatic POC collection from multiple sources

### 🧪 Additional Security Testing
- **XSS Testing**: Reflected and stored XSS vulnerability detection
- **Web Crawling**: Endpoint and parameter discovery
- **POC Testing**: Custom POC execution framework
- **AI Analysis**: Automated vulnerability prioritization and risk assessment

## Installation

### Prerequisites
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install external tools
sudo apt-get install nmap tor

# Install Go-based tools
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### Optional: Ollama for AI Features
```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Download a model
ollama pull llama2
```

## Configuration

Environment variables can be set to customize behavior:

```bash
# GitHub API (for POC/CVE search)
export GITHUB_API_TOKEN="your_token_here"

# Nmap
export NMAP_PORTS="21,22,23,25,80,443,445,3306,3389,5432,8000,8080,8443"

# Naabu
export NAABU_ENABLED="true"
export NAABU_TOP_PORTS="1000"
export NAABU_RATE="1000"

# Tor
export TOR_ENABLED="false"
export TOR_PROXY="socks5h://127.0.0.1:9050"
export TOR_CONTROL_PASSWORD="your_password"

# Gobuster
export GOBUSTER_THREADS="50"
export GOBUSTER_WORDLIST="/usr/share/wordlists/dirb/common.txt"

# Ollama
export OLLAMA_BASE_URL="http://localhost:11434"
export OLLAMA_MODEL="llama2"
```

## Usage

### Service Reconnaissance
```python
from task_recon_services import execute_service_recon_and_vuln_scan

results = execute_service_recon_and_vuln_scan("target.com")
```

### Gobuster Scanning
```python
from task_gobuster import execute_gobuster_scan

results = execute_gobuster_scan("https://target.com")
```

### CVE Hunting
```python
from cve_hunter import search_cve_vulnerabilities

results = search_cve_vulnerabilities("Apache", "2.4.49")
```

### Nuclei Template Generation
```python
from nuclei_generator import NucleiGenerator

generator = NucleiGenerator()
template = generator.generate_template(
    cve_id="CVE-2024-1234",
    cve_description="Remote code execution in XYZ",
    poc_context=poc_code,
    service_info={"service": "Apache", "version_info": "2.4.49"}
)
```

### Web Crawling
```python
from task_crawler import crawl_target

results = crawl_target("https://target.com", max_depth=3)
```

### XSS Testing
```python
from task_xss import test_xss_vulnerabilities

results = test_xss_vulnerabilities(
    url="https://target.com/search",
    parameters=["q", "search", "query"]
)
```

## Architecture

```
config.py              - Configuration management
ai_core.py             - AI interactions and command execution
git_analyzer.py        - Repository cloning and analysis
recon_cache.py         - Database caching layer

task_recon_services.py - Service reconnaissance with Naabu/Nmap
task_gobuster.py       - Directory brute-forcing with Tor
nuclei_generator.py    - Nuclei template generation
cve_hunter.py          - CVE search and template collection

recon_engine.py        - Reconnaissance orchestration
task_crawler.py        - Web crawling
task_xss.py            - XSS testing
custom.py              - Custom POC testing
pentest_env.py         - Environment management
task_master.py         - AI-powered task orchestration
```

## Database Schema

The system uses SQLite for caching:
- `cve_cache`: CVE information cache
- `search_cache`: Search results cache
- `subdomain_cache`: Discovered subdomains
- `service_cache`: Service fingerprints
- `template_cache`: Nuclei templates

## Security Features

### Gobuster Improvements
- ✅ Tor proxy with automatic rotation
- ✅ Connection retry and error handling
- ✅ 403 bypass with multiple techniques
- ✅ Windows reserved name filtering
- ✅ External URL filtering
- ✅ Generic error page detection
- ✅ Baseline signature matching

### Nuclei Template Quality
- ✅ Fake author detection (topscoder, grok, etc.)
- ✅ YAML structure validation
- ✅ CVE description matching
- ✅ Official template prioritization
- ✅ AI-powered template selection

### CVE Search
- ✅ Result caching (30-day default)
- ✅ Multiple search engines
- ✅ Automatic POC discovery
- ✅ Template quality filtering

## Contributing

This system follows security best practices:
1. No credential storage in code
2. Minimal modifications to working code
3. Backward compatibility preservation
4. Comprehensive error handling
5. Security-first design

## License

See repository license file.

## Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have permission to test target systems.
