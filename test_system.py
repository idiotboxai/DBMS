#!/usr/bin/env python3
"""
Test script to verify system functionality.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported."""
    print("\n" + "="*80)
    print("Testing Module Imports")
    print("="*80)
    
    modules = [
        'config',
        'ai_core',
        'git_analyzer',
        'recon_cache',
        'task_gobuster',
        'nuclei_generator',
        'cve_hunter',
        'task_recon_services',
        'recon_engine',
        'custom',
        'task_crawler',
        'task_xss',
        'pentest_env',
        'task_master',
    ]
    
    failed = []
    
    for module_name in modules:
        try:
            __import__(module_name)
            print(f"✅ {module_name}")
        except Exception as e:
            print(f"❌ {module_name}: {str(e)[:50]}")
            failed.append(module_name)
    
    if failed:
        print(f"\n⚠️  {len(failed)} modules failed to import")
        return False
    else:
        print(f"\n✅ All {len(modules)} modules imported successfully")
        return True


def test_config():
    """Test configuration loading."""
    print("\n" + "="*80)
    print("Testing Configuration")
    print("="*80)
    
    try:
        import config
        
        print(f"✅ TOR_ENABLED: {config.TOR_ENABLED}")
        print(f"✅ NAABU_ENABLED: {config.NAABU_ENABLED}")
        print(f"✅ NMAP_PORTS: {config.NMAP_PORTS}")
        print(f"✅ GOBUSTER_THREADS: {config.GOBUSTER_THREADS}")
        print(f"✅ DB_PATH: {config.DB_PATH}")
        print(f"✅ Windows reserved names: {len(config.WINDOWS_RESERVED_NAMES)} items")
        print(f"✅ Bypass methods: {', '.join(config.BYPASS_METHODS)}")
        print(f"✅ Fake authors: {', '.join(config.FAKE_AUTHORS)}")
        
        return True
    except Exception as e:
        print(f"❌ Configuration test failed: {str(e)}")
        return False


def test_cache():
    """Test cache database."""
    print("\n" + "="*80)
    print("Testing Cache Database")
    print("="*80)
    
    try:
        from recon_cache import get_cache
        
        cache = get_cache()
        print(f"✅ Cache initialized: {cache.db_path}")
        
        # Test CVE caching
        test_cve = {
            'cve_id': 'CVE-2024-TEST',
            'description': 'Test CVE',
            'severity': 'high'
        }
        
        cache.cache_cve('CVE-2024-TEST', test_cve)
        print(f"✅ CVE caching works")
        
        # Test search caching
        test_results = [{'url': 'http://example.com', 'title': 'Test'}]
        cache.cache_search_results('test query', test_results)
        print(f"✅ Search caching works")
        
        cache.close()
        
        return True
    except Exception as e:
        print(f"❌ Cache test failed: {str(e)}")
        return False


def test_tor_manager():
    """Test Tor proxy manager."""
    print("\n" + "="*80)
    print("Testing Tor Proxy Manager")
    print("="*80)
    
    try:
        from task_gobuster import TorProxyManager
        
        tor = TorProxyManager()
        print(f"✅ Tor manager initialized")
        print(f"   Enabled: {tor.enabled}")
        print(f"   Proxy: {tor.proxy_url}")
        
        if tor.enabled:
            print(f"   Testing connection...")
            result = tor.test_connection()
            print(f"   Connection test: {'✅' if result else '❌'}")
        else:
            print(f"   ⚠️  Tor not enabled (set TOR_ENABLED=true to test)")
        
        return True
    except Exception as e:
        print(f"❌ Tor manager test failed: {str(e)}")
        return False


def test_bypass_techniques():
    """Test 403 bypass techniques."""
    print("\n" + "="*80)
    print("Testing 403 Bypass Techniques")
    print("="*80)
    
    try:
        from task_gobuster import BypassTechniques
        
        headers = BypassTechniques.get_bypass_headers()
        print(f"✅ Header variations: {len(headers)} methods")
        
        path_vars = BypassTechniques.get_path_variations('/admin')
        print(f"✅ Path variations: {len(path_vars)} methods")
        
        methods = BypassTechniques.get_http_methods()
        print(f"✅ HTTP methods: {', '.join(methods)}")
        
        return True
    except Exception as e:
        print(f"❌ Bypass techniques test failed: {str(e)}")
        return False


def test_nuclei_generator():
    """Test Nuclei template generator."""
    print("\n" + "="*80)
    print("Testing Nuclei Generator")
    print("="*80)
    
    try:
        from nuclei_generator import NucleiGenerator, POCAnalyzer, TemplateValidator
        
        analyzer = POCAnalyzer()
        print(f"✅ POC analyzer initialized")
        
        # Test vulnerability type detection
        test_content = "This is a SQL injection vulnerability using UNION SELECT"
        vuln_type = analyzer.detect_vulnerability_type(test_content, "")
        print(f"✅ Vulnerability detection: {vuln_type}")
        
        validator = TemplateValidator()
        print(f"✅ Template validator initialized")
        
        generator = NucleiGenerator()
        print(f"✅ Nuclei generator initialized")
        
        return True
    except Exception as e:
        print(f"❌ Nuclei generator test failed: {str(e)}")
        return False


def test_cve_hunter():
    """Test CVE hunter."""
    print("\n" + "="*80)
    print("Testing CVE Hunter")
    print("="*80)
    
    try:
        from cve_hunter import CVEHunter
        
        hunter = CVEHunter()
        print(f"✅ CVE hunter initialized")
        print(f"   Cache available: {hunter.cache is not None}")
        print(f"   Generator available: {hunter.generator is not None}")
        print(f"   Validator available: {hunter.validator is not None}")
        
        return True
    except Exception as e:
        print(f"❌ CVE hunter test failed: {str(e)}")
        return False


def test_recon_engine():
    """Test reconnaissance engine."""
    print("\n" + "="*80)
    print("Testing Reconnaissance Engine")
    print("="*80)
    
    try:
        from recon_engine import ReconEngine, filter_subdomains
        
        # Test subdomain filtering
        discovered = ['api.example.com', 'www.example.com', 'evil.com']
        input_domains = ['example.com']
        
        filtered = filter_subdomains(discovered, input_domains)
        print(f"✅ Subdomain filtering: {len(discovered)} → {len(filtered)}")
        
        # Test recon engine
        engine = ReconEngine(['example.com'])
        print(f"✅ Recon engine initialized")
        
        engine.add_subdomains(['test.example.com', 'api.example.com'])
        print(f"✅ Subdomains added: {len(engine.discovered_subdomains)}")
        
        return True
    except Exception as e:
        print(f"❌ Recon engine test failed: {str(e)}")
        return False


def test_pentest_env():
    """Test pentest environment."""
    print("\n" + "="*80)
    print("Testing Pentest Environment")
    print("="*80)
    
    try:
        from pentest_env import PentestEnvironment
        
        env = PentestEnvironment('test-target')
        print(f"✅ Environment initialized")
        print(f"   Target dir: {env.target_dir}")
        
        tools = env.get_installed_tools()
        installed = [tool for tool, status in tools.items() if status]
        print(f"✅ Found {len(installed)} installed tools: {', '.join(installed)}")
        
        return True
    except Exception as e:
        print(f"❌ Pentest env test failed: {str(e)}")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("🧪 DBMS Security Scanning System - Test Suite")
    print("="*80)
    
    tests = [
        ("Module Imports", test_imports),
        ("Configuration", test_config),
        ("Cache Database", test_cache),
        ("Tor Manager", test_tor_manager),
        ("Bypass Techniques", test_bypass_techniques),
        ("Nuclei Generator", test_nuclei_generator),
        ("CVE Hunter", test_cve_hunter),
        ("Recon Engine", test_recon_engine),
        ("Pentest Environment", test_pentest_env),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ {test_name} crashed: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*80)
    print("📊 Test Summary")
    print("="*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print("\n" + "="*80)
    print(f"Results: {passed}/{total} tests passed")
    print("="*80 + "\n")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print(f"⚠️  {total - passed} tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
