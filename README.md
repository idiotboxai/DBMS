# Security Scanning Framework

A production-quality Python framework for automated security scanning with smart directory enumeration, vulnerability detection, and port-specific scanning capabilities.

## Features

### Core Capabilities
- **Smart Gobuster Scanning**: Directory enumeration with advanced false positive filtering
- **Threading & Connection Management**: Controlled concurrent scanning with rate limiting
- **Redirect Chain Detection**: Tracks and validates HTTP redirect sequences
- **False Positive Filtering**: Eliminates generic error pages and reflected paths
- **Database Persistence**: SQLite storage with JSON serialization for complex data
- **Port-Specific Scanning**: Supports scanning across different ports with proper URL construction
- **Tor Integration**: Optional Tor proxy support for anonymous scanning

### Key Components

#### 1. task_gobuster.py
Smart directory scanning with comprehensive filtering:
- `ConnectionPool`: Thread-safe connection management with rate limiting
- `get_redirect_chain()`: Follows HTTP redirects up to configurable limit
- `is_homepage_redirect()`: Detects redirects to homepage/login pages
- `is_generic_error_page()`: Filters out generic 404/403 error pages
- `is_reflected_path()`: Identifies reflected path parameters (prevents false positives)
- `execute_gobuster_scan_smart()`: Main scanning function with all features integrated

#### 2. pentest_env.py
Environment setup and orchestration:
- `PentestEnvironment`: Manages directory structure and tool availability
- Imports and exposes `execute_gobuster_scan_smart` from task_gobuster
- CLI interface for quick scanning

#### 3. Supporting Modules
- **config.py**: Centralized configuration (threads, timeouts, rate limits)
- **ai_core.py**: Command execution and AI integration stubs
- **git_analyzer.py**: Repository cloning and analysis for POC discovery

## Installation

```bash
# Clone repository
git clone https://github.com/idiotboxai/DBMS.git
cd DBMS

# Install dependencies
pip install requests

# Optional: Install Tor for anonymous scanning
# sudo apt-get install tor
```

## Usage

### Basic Scanning

```python
from task_gobuster import execute_gobuster_scan_smart

# Scan a target
findings = execute_gobuster_scan_smart(
    target="example.com",
    port=80,
    wordlist=['/admin', '/api', '/config'],
    use_tor=False
)

print(f"Found {len(findings)} valid paths")
```

### Using PentestEnvironment

```python
from pentest_env import PentestEnvironment

# Setup environment
env = PentestEnvironment("example.com")

# Check status
status = env.get_status()
print(status)

# Run scan
results = env.run_gobuster_scan(port=443, use_tor=False)
```

### Command Line

```bash
# Scan on default port 80
python pentest_env.py example.com

# Scan on specific port
python pentest_env.py example.com 443

# Scan on multiple ports
python pentest_env.py example.com 8080
```

## Architecture

### Threading Model
- Maximum concurrent connections: 5 (configurable in config.py)
- Rate limiting: 0.5 seconds between requests
- Thread-safe semaphore for connection pooling
- Automatic cleanup on completion

### Redirect Handling
1. Follows redirects manually (max 10 hops)
2. Records full redirect chain
3. Detects circular redirects
4. Validates final destination
5. Filters homepage/login redirects

### False Positive Filtering

**Generic Error Pages:**
- Detects common 404/403 patterns
- Matches server-specific error signatures (nginx, Apache, IIS)
- Checks content length thresholds
- Requires multiple signature matches

**Reflected Paths:**
- Extracts path components from URL
- Searches for reflection in response content
- Prevents false positives from error messages

**Homepage Redirects:**
- Collects baseline signatures from known homepage paths
- Compares final URL and content length
- Detects redirects to /, /index.*, /home, /login

### Database Schema

```sql
CREATE TABLE gobuster_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    port INTEGER,
    path TEXT,
    url TEXT,
    status_code INTEGER,
    content_length INTEGER,
    redirect_chain TEXT,  -- JSON serialized
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

## Configuration

Edit `config.py` to customize:

```python
NMAP_PORTS = "80,443,8000,8080,8443"
TOR_PROXY = "socks5h://127.0.0.1:9050"
MAX_THREADS = 5
REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 0.5
MAX_REDIRECTS = 10
DATABASE_PATH = "recon_cache.db"
```

## Testing

Run the test suite:

```bash
python test_functionality.py
```

Tests cover:
- Connection pool operations
- Redirect chain detection
- Generic error page filtering
- Reflected path detection
- Database operations
- Environment setup
- Import chain validation

## Key Design Decisions

### 1. JSON Serialization for Lists
SQLite doesn't support list parameters directly. Solution:
```python
redirect_chain_json = json.dumps(finding.get('redirect_chain', []))
cursor.execute("INSERT INTO ... VALUES (?)", (redirect_chain_json,))
```

### 2. Connection Pooling
Prevents connection exhaustion:
- Semaphore limits concurrent connections
- Rate limiter prevents server overload
- Automatic acquire/release in try/finally blocks

### 3. Redirect Chain Validation
Prevents false positives from redirects:
- Manual redirect following (not requests.Session)
- Records full chain for analysis
- Validates final destination
- Compares against baseline signatures

### 4. Thread Safety
All shared resources are protected:
- Semaphore for connection pool
- Lock for rate limiter
- Thread-local sessions avoided (new session per request)

## Troubleshooting

### "Error binding parameter 2: type 'list' is not supported"
This was fixed by JSON serializing lists before database insertion.

### Connection exhaustion
Reduce `MAX_THREADS` in config.py or increase `RATE_LIMIT_DELAY`.

### Too many false positives
Adjust error page signatures in `is_generic_error_page()` function.

### Tor connection failures
Ensure Tor is running: `sudo service tor status`
Check proxy setting: `socks5h://` (not `socks5://`) for DNS through Tor

## Future Enhancements

- [ ] Add ffuf integration alongside Gobuster
- [ ] Implement 403 bypass techniques
- [ ] Add Windows reserved name filtering (CON, PRN, AUX, etc.)
- [ ] Support custom header injection
- [ ] Add progress bar for long scans
- [ ] Export results to JSON/CSV/HTML

## License

This project is part of the DBMS repository.

## Contributing

Contributions welcome! Key areas:
1. Additional error page signatures
2. More sophisticated false positive detection
3. Performance optimizations
4. Additional output formats
