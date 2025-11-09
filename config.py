# config.py
"""
Configuration settings for the security scanning system.
"""

import os

# GitHub API Configuration
GITHUB_API_TOKEN = os.environ.get("GITHUB_API_TOKEN", "")

# Nmap Configuration
NMAP_PORTS = os.environ.get("NMAP_PORTS", "21,22,23,25,80,443,445,3306,3389,5432,8000,8080,8443")

# Naabu Configuration
NAABU_ENABLED = os.environ.get("NAABU_ENABLED", "true").lower() == "true"
NAABU_TOP_PORTS = os.environ.get("NAABU_TOP_PORTS", "1000")
NAABU_RATE = os.environ.get("NAABU_RATE", "1000")
NAABU_TIMEOUT = int(os.environ.get("NAABU_TIMEOUT", "5"))

# Tor Configuration
TOR_ENABLED = os.environ.get("TOR_ENABLED", "false").lower() == "true"
TOR_PROXY = os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050")
TOR_CONTROL_PORT = int(os.environ.get("TOR_CONTROL_PORT", "9051"))
TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "")
TOR_ROTATION_INTERVAL = int(os.environ.get("TOR_ROTATION_INTERVAL", "300"))  # seconds

# Gobuster Configuration
GOBUSTER_THREADS = int(os.environ.get("GOBUSTER_THREADS", "50"))
GOBUSTER_TIMEOUT = int(os.environ.get("GOBUSTER_TIMEOUT", "10"))
GOBUSTER_DELAY = os.environ.get("GOBUSTER_DELAY", "0ms")
GOBUSTER_WORDLIST = os.environ.get("GOBUSTER_WORDLIST", "/usr/share/wordlists/dirb/common.txt")

# Windows Reserved Names (for filtering)
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

# 403 Bypass Techniques Configuration
BYPASS_METHODS = [
    "headers",      # X-Original-URL, X-Rewrite-URL, etc.
    "path",         # Path manipulation (/../, /./, etc.)
    "method",       # HTTP method changes (POST, PUT, etc.)
    "case",         # Case manipulation
    "encoding",     # URL encoding variations
]

# Nuclei Configuration
NUCLEI_TEMPLATE_DIR = os.environ.get("NUCLEI_TEMPLATE_DIR", "nuclei-templates")
NUCLEI_SEVERITY = os.environ.get("NUCLEI_SEVERITY", "critical,high,medium")

# AI-Generated Template Filters (fake authors to reject)
FAKE_AUTHORS = [
    "topscoder",
    "grok",
    "ai-generated",
    "automated",
    "chatgpt",
    "copilot",
]

# CVE Cache Configuration
CVE_CACHE_EXPIRY_DAYS = int(os.environ.get("CVE_CACHE_EXPIRY_DAYS", "7"))
SEARCH_CACHE_EXPIRY_DAYS = int(os.environ.get("SEARCH_CACHE_EXPIRY_DAYS", "30"))

# Ollama Configuration
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama2")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "120"))

# Subdomain Filtering
FILTER_SUBDOMAINS = os.environ.get("FILTER_SUBDOMAINS", "true").lower() == "true"

# Recon Directory
RECON_DIR = os.environ.get("RECON_DIR", "Recon")

# Database Configuration
DB_PATH = os.environ.get("DB_PATH", os.path.join(RECON_DIR, "recon_cache.db"))

# Thread Pool Configuration
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "5"))
CVE_MAX_WORKERS = int(os.environ.get("CVE_MAX_WORKERS", "3"))

# Request Configuration
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "10"))
REQUEST_RETRIES = int(os.environ.get("REQUEST_RETRIES", "3"))
REQUEST_USER_AGENT = os.environ.get(
    "REQUEST_USER_AGENT", 
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Generic Error Page Signatures
GENERIC_ERROR_SIGNATURES = [
    "404 not found",
    "page not found",
    "file not found",
    "error 404",
    "not found on this server",
    "the requested url was not found",
    "no such file or directory",
    "403 forbidden",
    "access denied",
    "forbidden",
    "you don't have permission",
    "directory index forbidden",
    "500 internal server error",
    "internal server error",
    "something went wrong",
    "unexpected error",
    "bad gateway",
    "service unavailable",
]
