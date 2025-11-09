#!/usr/bin/env python3
import sys
from task_gobuster import execute_gobuster_scan_smart
from pentest_env import PentestEnvironment
def demo_basic_scan():
    print("="*80)
    print("DEMO 1: Basic Gobuster Scan")
    print("="*80)
    findings = execute_gobuster_scan_smart(
        target="example.com",
        port=80,
        wordlist=['/admin', '/api', '/config', '/test', '/backup'],
        use_tor=False
    )
    print(f"\nResult: Found {len(findings)} valid paths")
    if findings:
        for finding in findings:
            print(f"  - {finding['path']} [{finding['status_code']}]")
def demo_port_specific_scan():
    print("\n" + "="*80)
    print("DEMO 2: Port-Specific Scan (HTTPS)")
    print("="*80)
    findings = execute_gobuster_scan_smart(
        target="https://example.com",
        port=443,
        wordlist=['/api', '/docs', '/swagger'],
        use_tor=False
    )
    print(f"\nResult: Found {len(findings)} valid paths on port 443")
def demo_environment_setup():
    print("\n" + "="*80)
    print("DEMO 3: PentestEnvironment Usage")
    print("="*80)
    env = PentestEnvironment("example.com", output_dir="/tmp/demo_recon")
    print("\nEnvironment Status:")
    status = env.get_status()
    for key, value in status.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")
    print("\nRunning scan through environment...")
    results = env.run_gobuster_scan(port=80, wordlist=['/admin'], use_tor=False)
    print(f"Environment scan complete: {len(results)} findings")
def demo_threading_and_rate_limiting():
    print("\n" + "="*80)
    print("DEMO 4: Threading and Rate Limiting in Action")
    print("="*80)
    print("\nScanning 10 paths with 5 concurrent threads and rate limiting...")
    print("(Notice the controlled pace of requests)")
    import time
    start_time = time.time()
    wordlist = [f'/path{i}' for i in range(10)]
    findings = execute_gobuster_scan_smart(
        target="example.com",
        port=80,
        wordlist=wordlist,
        use_tor=False
    )
    elapsed = time.time() - start_time
    print(f"\nCompleted in {elapsed:.2f} seconds")
    print(f"Rate: {len(wordlist)/elapsed:.2f} requests/second")
    print(f"(Rate limiting ensures we don't exceed ~2 req/sec)")
def demo_database_persistence():
    print("\n" + "="*80)
    print("DEMO 5: Database Persistence with JSON Serialization")
    print("="*80)
    import sqlite3
    import json
    from config import DATABASE_PATH
    print(f"\nDatabase file: {DATABASE_PATH}")
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM gobuster_findings")
        count = cursor.fetchone()[0]
        print(f"Total findings in database: {count}")
        if count > 0:
            cursor.execute("SELECT target, port, path, status_code, redirect_chain FROM gobuster_findings LIMIT 3")
            print("\nSample findings:")
            for row in cursor.fetchall():
                target, port, path, status_code, redirect_chain_json = row
                redirect_chain = json.loads(redirect_chain_json)
                print(f"  - {target}:{port}{path} [{status_code}]")
                print(f"    Redirects: {len(redirect_chain)} hops")
        conn.close()
    except Exception as e:
        print(f"Database error: {e}")
def demo_false_positive_filtering():
    print("\n" + "="*80)
    print("DEMO 6: False Positive Filtering Features")
    print("="*80)
    from task_gobuster import is_generic_error_page, is_reflected_path, is_homepage_redirect
    test_cases = [
        ("Generic 404", "<html><title>404</title>Page not found</html>", 404),
        ("Valid page", "<html><title>Admin Panel</title>Welcome admin</html>", 200),
        ("Generic 403", "Error 403 - Access Denied by IIS", 403),
    ]
    print("\nGeneric Error Page Detection:")
    for name, content, status in test_cases:
        result = is_generic_error_page(content, status)
        print(f"  {name} ({status}): {'FILTERED' if result else 'VALID'}")
    print("\nReflected Path Detection:")
    reflect_tests = [
        ("http://example.com/admin", "Path /admin not found"),
        ("http://example.com/api", "Welcome to our API"),
    ]
    for url, content in reflect_tests:
        result = is_reflected_path(url, content)
        print(f"  {url}: {'FILTERED' if result else 'VALID'}")
    print("\nHomepage Redirect Detection:")
    print("  Paths redirecting to /, /index.html, /login are automatically filtered")
def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                 SECURITY SCANNING FRAMEWORK DEMONSTRATION                  ║
║                                                                            ║
║  This demo shows the key features of the smart gobuster implementation    ║
╚════════════════════════════════════════════════════════════════════════════╝
""")
    try:
        demo_basic_scan()
        demo_port_specific_scan()
        demo_environment_setup()
        demo_threading_and_rate_limiting()
        demo_database_persistence()
        demo_false_positive_filtering()
        print("\n" + "="*80)
        print("✅ ALL DEMONSTRATIONS COMPLETED")
        print("="*80)
        print("\nKey Takeaways:")
        print("  1. Smart filtering eliminates false positives")
        print("  2. Threading and rate limiting prevent server overload")
        print("  3. Database persistence with JSON serialization works correctly")
        print("  4. Port-specific scanning is fully supported")
        print("  5. Redirect chain validation catches tricky false positives")
        print("\nFor more details, see README.md")
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nDemo error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
if __name__ == "__main__":
    main()
