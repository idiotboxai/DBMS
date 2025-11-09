# Quick Start Guide

Get started with the Security Scanning Framework in 5 minutes.

## Installation

```bash
# Clone repository
git clone https://github.com/idiotboxai/DBMS.git
cd DBMS

# Install dependencies
pip install requests
```

## Basic Usage

### 1. Simple Scan

```python
from task_gobuster import execute_gobuster_scan_smart

# Scan a target
findings = execute_gobuster_scan_smart(
    target="example.com",
    port=80,
    wordlist=['/admin', '/api', '/backup'],
    use_tor=False
)

# Print results
for finding in findings:
    print(f"{finding['path']} - {finding['status_code']}")
```

### 2. Using Environment

```python
from pentest_env import PentestEnvironment

# Setup
env = PentestEnvironment("example.com")

# Scan
results = env.run_gobuster_scan(port=443)
print(f"Found {len(results)} paths")
```

### 3. Command Line

```bash
# Default port 80
python pentest_env.py example.com

# Specific port
python pentest_env.py example.com 443
```

## Configuration

Edit `config.py` to customize:

```python
MAX_THREADS = 5              # Concurrent connections
RATE_LIMIT_DELAY = 0.5       # Seconds between requests
MAX_REDIRECTS = 10           # Maximum redirect hops
REQUEST_TIMEOUT = 10         # Timeout per request
```

## Features

✅ **Smart Filtering**
- Removes generic 404/403 pages
- Filters reflected paths
- Detects homepage redirects

✅ **Threading**
- Connection pooling (max 5)
- Rate limiting (prevents overload)
- Thread-safe operations

✅ **Database Storage**
- SQLite persistence
- JSON serialization for lists
- Query by target/port

✅ **Port Support**
- Any port (80, 443, 8080, etc.)
- Automatic scheme detection
- HTTPS support

## Common Tasks

### Scan Multiple Ports

```python
ports = [80, 443, 8080, 8443]
for port in ports:
    findings = execute_gobuster_scan_smart("example.com", port)
    print(f"Port {port}: {len(findings)} findings")
```

### Custom Wordlist

```python
wordlist = [
    '/admin', '/api', '/backup', '/config',
    '/dev', '/test', '/upload', '/files',
    '/.git', '/dashboard'
]

findings = execute_gobuster_scan_smart(
    "example.com", 
    wordlist=wordlist
)
```

### With Tor Proxy

```python
# Requires Tor running on 9050
findings = execute_gobuster_scan_smart(
    "example.com",
    use_tor=True
)
```

### Query Database

```python
import sqlite3
import json

conn = sqlite3.connect("recon_cache.db")
cursor = conn.cursor()

# Get all findings for a target
cursor.execute(
    "SELECT * FROM gobuster_findings WHERE target = ?",
    ("example.com",)
)

for row in cursor.fetchall():
    print(row)

conn.close()
```

## Testing

Run tests to verify installation:

```bash
# Unit tests
python test_functionality.py

# Demonstrations
python demo_usage.py
```

## Troubleshooting

### Import Error

```python
# Add current directory to path
import sys
sys.path.insert(0, '/path/to/DBMS')
```

### Database Locked

```python
# Close existing connections
conn.close()
```

### Rate Limit Too Fast

```python
# In config.py, increase delay
RATE_LIMIT_DELAY = 1.0  # 1 second
```

### Connection Timeout

```python
# In config.py, increase timeout
REQUEST_TIMEOUT = 30  # 30 seconds
```

## Next Steps

1. Read [README.md](README.md) for detailed documentation
2. Review [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for technical details
3. Check [VERIFICATION.md](VERIFICATION.md) for requirements proof

## Support

For issues or questions:
1. Check documentation files
2. Review test examples
3. Run demo script for usage examples

## Performance Tips

1. **Reduce threads** if hitting rate limits:
   ```python
   MAX_THREADS = 3
   ```

2. **Increase delay** for slower targets:
   ```python
   RATE_LIMIT_DELAY = 1.0
   ```

3. **Smaller wordlists** for faster scans:
   ```python
   wordlist = ['/admin', '/api']  # Top paths only
   ```

4. **Query database** instead of re-scanning:
   ```sql
   SELECT * FROM gobuster_findings 
   WHERE target = 'example.com' 
   AND timestamp > datetime('now', '-1 day');
   ```

## License

Part of the DBMS repository.
