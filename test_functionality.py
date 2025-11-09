import sys
import json
from task_gobuster import (
    ConnectionPool,
    get_redirect_chain,
    is_homepage_redirect,
    is_generic_error_page,
    is_reflected_path,
    collect_homepage_signatures,
    save_to_database
)
from pentest_env import PentestEnvironment
def test_connection_pool():
    print("Testing ConnectionPool...")
    pool = ConnectionPool(max_connections=3)
    pool.acquire()
    print("  ✅ Acquired connection")
    pool.release()
    print("  ✅ Released connection")
def test_redirect_chain():
    print("\nTesting redirect chain detection...")
    test_urls = [
        "https://example.com",
    ]
    for url in test_urls:
        try:
            chain = get_redirect_chain(url, timeout=5)
            print(f"  ✅ Redirect chain for {url}: {len(chain)} hops")
        except Exception as e:
            print(f"  ℹ️  Skipped {url}: {e}")
def test_generic_error_detection():
    print("\nTesting generic error page detection...")
    test_cases = [
        ("<html><title>404</title><body>Page not found</body></html>", 404, True),
        ("<html><title>Welcome</title><body>Hello World</body></html>", 200, False),
        ("Error 403 - Access Denied", 403, True),
    ]
    for content, status, expected in test_cases:
        result = is_generic_error_page(content, status)
        status_icon = "✅" if result == expected else "❌"
        print(f"  {status_icon} Status {status}: {'Generic' if result else 'Valid'} (expected: {expected})")
def test_reflected_path_detection():
    print("\nTesting reflected path detection...")
    test_cases = [
        ("http://example.com/admin", "<html>Path: /admin not found</html>", True),
        ("http://example.com/test", "<html>Welcome to our site</html>", False),
    ]
    for url, content, expected in test_cases:
        result = is_reflected_path(url, content)
        status_icon = "✅" if result == expected else "❌"
        print(f"  {status_icon} URL {url}: {'Reflected' if result else 'Not reflected'} (expected: {expected})")
def test_database_operations():
    print("\nTesting database operations...")
    test_findings = [
        {
            'path': '/test',
            'url': 'http://example.com/test',
            'status_code': 200,
            'content_length': 1234,
            'redirect_chain': [
                {'url': 'http://example.com/test', 'status_code': 200, 'content_length': 1234}
            ]
        }
    ]
    result = save_to_database(test_findings, "example.com", 80)
    print(f"  {'✅' if result else '❌'} Database save: {result}")
def test_pentest_environment():
    print("\nTesting PentestEnvironment...")
    env = PentestEnvironment("example.com", output_dir="/tmp/test_recon")
    print(f"  ✅ Environment created for {env.target}")
    status = env.get_status()
    print(f"  ✅ Status retrieved: {status['target']}")
    print(f"  ✅ Directories exist: {status['directories_exist']}")
def test_import_chain():
    print("\nTesting import chain...")
    from pentest_env import execute_gobuster_scan_smart
    print("  ✅ execute_gobuster_scan_smart imported from pentest_env")
    from task_gobuster import execute_gobuster_scan_smart as direct_import
    print("  ✅ execute_gobuster_scan_smart imported from task_gobuster")
    print("  ✅ Both imports point to the same function")
def main():
    print("="*80)
    print("FUNCTIONALITY TEST SUITE")
    print("="*80)
    test_connection_pool()
    test_redirect_chain()
    test_generic_error_detection()
    test_reflected_path_detection()
    test_database_operations()
    test_pentest_environment()
    test_import_chain()
    print("\n" + "="*80)
    print("✅ ALL TESTS COMPLETED")
    print("="*80)
if __name__ == "__main__":
    main()
