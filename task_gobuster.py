import requests
import json
import time
import sqlite3
import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import TOR_PROXY, MAX_THREADS, REQUEST_TIMEOUT, RATE_LIMIT_DELAY, MAX_REDIRECTS, DATABASE_PATH
class ConnectionPool:
    def __init__(self, max_connections=5):
        self.max_connections = max_connections
        self.semaphore = threading.Semaphore(max_connections)
        self.rate_limiter = threading.Lock()
        self.last_request_time = 0
    def acquire(self):
        self.semaphore.acquire()
        with self.rate_limiter:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < RATE_LIMIT_DELAY:
                time.sleep(RATE_LIMIT_DELAY - time_since_last)
            self.last_request_time = time.time()
    def release(self):
        self.semaphore.release()
def get_redirect_chain(url, timeout=REQUEST_TIMEOUT, max_redirects=MAX_REDIRECTS):
    chain = []
    current_url = url
    session = requests.Session()
    session.max_redirects = 0
    try:
        for _ in range(max_redirects):
            try:
                response = session.get(current_url, allow_redirects=False, timeout=timeout, verify=False)
                chain.append({
                    'url': current_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content)
                })
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if not location:
                        break
                    if location.startswith('/'):
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif location.startswith('http'):
                        current_url = location
                    else:
                        current_url = urljoin(current_url, location)
                else:
                    break
            except requests.RequestException:
                break
    except Exception as e:
        print(f"Redirect chain error: {e}")
    return chain
def is_homepage_redirect(chain, homepage_signatures):
    if not chain:
        return False
    final_url = chain[-1]['url']
    final_status = chain[-1]['status_code']
    final_length = chain[-1]['content_length']
    parsed_final = urlparse(final_url)
    if parsed_final.path in ['/', '/index.html', '/index.php', '/home', '/login']:
        return True
    for sig in homepage_signatures:
        if abs(final_length - sig['content_length']) < 100 and final_status == sig['status_code']:
            return True
    return False
def is_generic_error_page(content, status_code):
    if not content:
        return True
    error_signatures = [
        '404 Not Found',
        '403 Forbidden',
        'Page not found',
        'Access Denied',
        'The requested URL was not found',
        'Error 404',
        'Error 403',
        'File not found',
        'Directory listing denied',
        '<title>404</title>',
        '<title>403</title>',
        'nginx/1.',
        'Apache/2.',
        'IIS Windows Server',
    ]
    content_lower = content.lower()
    signature_count = sum(1 for sig in error_signatures if sig.lower() in content_lower)
    if signature_count >= 2:
        return True
    if status_code in [403, 404] and len(content) < 500:
        return True
    return False
def is_reflected_path(url, content):
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == '/':
        return False
    path_parts = path.strip('/').split('/')
    content_lower = content.lower() if content else ''
    for part in path_parts:
        if len(part) > 3 and part.lower() in content_lower:
            return True
    return False
def scan_path(base_url, path, pool, homepage_signatures, proxies=None):
    pool.acquire()
    try:
        url = urljoin(base_url, path)
        chain = get_redirect_chain(url, timeout=REQUEST_TIMEOUT)
        if not chain:
            return None
        final_response = chain[-1]
        if is_homepage_redirect(chain, homepage_signatures):
            return None
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False, proxies=proxies)
            if is_generic_error_page(response.text, response.status_code):
                return None
            if is_reflected_path(url, response.text):
                return None
            if response.status_code == 200:
                return {
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'redirect_chain': chain
                }
        except:
            pass
        return None
    finally:
        pool.release()
def collect_homepage_signatures(base_url):
    signatures = []
    homepage_paths = ['/', '/index.html', '/index.php', '/home']
    for path in homepage_paths:
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            signatures.append({
                'path': path,
                'status_code': response.status_code,
                'content_length': len(response.content)
            })
        except:
            continue
    return signatures
def save_to_database(findings, target, port):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS gobuster_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                path TEXT,
                url TEXT,
                status_code INTEGER,
                content_length INTEGER,
                redirect_chain TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        for finding in findings:
            redirect_chain_json = json.dumps(finding.get('redirect_chain', []))
            cursor.execute('''
                INSERT INTO gobuster_findings 
                (target, port, path, url, status_code, content_length, redirect_chain)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                target,
                port,
                finding['path'],
                finding['url'],
                finding['status_code'],
                finding['content_length'],
                redirect_chain_json
            ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Database error: {e}")
        return False
def execute_gobuster_scan_smart(target, port=80, wordlist=None, use_tor=False):
    print(f"\n{'='*80}")
    print(f"🔍 SMART GOBUSTER SCAN")
    print(f"Target: {target}:{port}")
    print(f"Using Tor: {use_tor}")
    print(f"{'='*80}\n")
    parsed = urlparse(target)
    if not parsed.scheme:
        scheme = 'https' if port == 443 else 'http'
        base_url = f"{scheme}://{target}:{port}"
    else:
        base_url = target
    proxies = {'http': TOR_PROXY, 'https': TOR_PROXY} if use_tor else None
    print("[BASELINE] Collecting homepage signatures...")
    homepage_signatures = collect_homepage_signatures(base_url)
    print(f"[BASELINE] Collected {len(homepage_signatures)} signatures")
    if wordlist is None:
        wordlist = [
            '/admin',
            '/backup',
            '/config',
            '/api',
            '/test',
            '/dev',
            '/uploads',
            '/files',
            '/.git',
            '/dashboard'
        ]
    print(f"[SCAN] Starting scan with {len(wordlist)} paths...")
    print(f"[THREADS] Using {MAX_THREADS} concurrent threads")
    pool = ConnectionPool(max_connections=MAX_THREADS)
    findings = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(scan_path, base_url, path, pool, homepage_signatures, proxies): path 
            for path in wordlist
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    findings.append(result)
                    print(f"  ✅ Found: {result['path']} [{result['status_code']}]")
            except Exception as e:
                print(f"  ❌ Scan error: {e}")
    print(f"\n[RESULTS] Found {len(findings)} valid paths")
    if findings:
        print("[DATABASE] Saving results...")
        if save_to_database(findings, target, port):
            print("[DATABASE] ✅ Results saved")
        else:
            print("[DATABASE] ❌ Save failed")
    print(f"\n{'='*80}")
    print("✅ SCAN COMPLETE")
    print(f"{'='*80}\n")
    return findings
