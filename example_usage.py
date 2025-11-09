#!/usr/bin/env python3
"""
Example usage of the DBMS Security Scanning System.

This script demonstrates how to use various components of the system.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def example_service_scan():
    """Example: Service reconnaissance with Naabu and Nmap."""
    print("\n" + "="*80)
    print("Example 1: Service Reconnaissance")
    print("="*80 + "\n")
    
    from task_recon_services import execute_service_recon_and_vuln_scan
    
    # Note: Replace with actual target for real use
    # results = execute_service_recon_and_vuln_scan("scanme.nmap.org")
    
    print("Usage:")
    print("  from task_recon_services import execute_service_recon_and_vuln_scan")
    print("  results = execute_service_recon_and_vuln_scan('target.com')")
    print("\nFeatures:")
    print("  - Fast port discovery with Naabu (if enabled)")
    print("  - Detailed service detection with Nmap")
    print("  - CVE extraction from scan results")
    print("  - Parallel POC searching")


def example_gobuster_scan():
    """Example: Directory brute-forcing with Gobuster."""
    print("\n" + "="*80)
    print("Example 2: Gobuster Directory Scanning")
    print("="*80 + "\n")
    
    from task_gobuster import execute_gobuster_scan
    
    print("Usage:")
    print("  from task_gobuster import execute_gobuster_scan")
    print("  results = execute_gobuster_scan('https://target.com')")
    print("\nFeatures:")
    print("  - Optional Tor proxy support")
    print("  - 403 bypass techniques (headers, paths, methods)")
    print("  - Windows reserved name filtering")
    print("  - Baseline signature collection")
    print("  - Redirect handling")
    print("  - Generic error page detection")


def example_cve_hunting():
    """Example: CVE hunting for a service."""
    print("\n" + "="*80)
    print("Example 3: CVE Hunting")
    print("="*80 + "\n")
    
    from cve_hunter import search_cve_vulnerabilities, get_cve_info
    
    print("Usage:")
    print("  from cve_hunter import search_cve_vulnerabilities, get_cve_info")
    print("")
    print("  # Search for vulnerabilities in a specific service")
    print("  results = search_cve_vulnerabilities('Apache', '2.4.49')")
    print("")
    print("  # Get detailed info about a specific CVE")
    print("  cve_info = get_cve_info('CVE-2021-41773')")
    print("\nFeatures:")
    print("  - Multi-source search (NVD, DuckDuckGo, PacketStorm, GitHub)")
    print("  - Result caching (30-day default)")
    print("  - POC discovery and collection")
    print("  - Existing Nuclei template search")


def example_nuclei_generation():
    """Example: Nuclei template generation."""
    print("\n" + "="*80)
    print("Example 4: Nuclei Template Generation")
    print("="*80 + "\n")
    
    from nuclei_generator import NucleiGenerator
    
    print("Usage:")
    print("  from nuclei_generator import NucleiGenerator")
    print("")
    print("  generator = NucleiGenerator()")
    print("  template = generator.generate_template(")
    print("      cve_id='CVE-2024-1234',")
    print("      cve_description='Remote code execution vulnerability',")
    print("      poc_context=poc_code,  # From git_analyzer")
    print("      service_info={'service': 'Apache', 'version_info': '2.4.49'}")
    print("  )")
    print("\nFeatures:")
    print("  - POC file prioritization")
    print("  - Structured information extraction")
    print("  - Vulnerability type detection")
    print("  - Fake author filtering")
    print("  - AI-powered template generation")


def example_recon_engine():
    """Example: Reconnaissance engine with subdomain filtering."""
    print("\n" + "="*80)
    print("Example 5: Reconnaissance Engine")
    print("="*80 + "\n")
    
    from recon_engine import ReconEngine
    
    print("Usage:")
    print("  from recon_engine import ReconEngine")
    print("")
    print("  engine = ReconEngine(['example.com'])")
    print("  ")
    print("  # Add discovered subdomains (automatically filtered)")
    print("  engine.add_subdomains([")
    print("      'api.example.com',")
    print("      'www.example.com',")
    print("      'evil.com'  # This will be filtered out")
    print("  ])")
    print("  ")
    print("  # Get summary")
    print("  summary = engine.get_summary()")
    print("\nFeatures:")
    print("  - Automatic subdomain filtering")
    print("  - Scope validation")
    print("  - Deduplication")
    print("  - Summary reporting")


def example_web_crawling():
    """Example: Web crawling for endpoint discovery."""
    print("\n" + "="*80)
    print("Example 6: Web Crawling")
    print("="*80 + "\n")
    
    from task_crawler import crawl_target
    
    print("Usage:")
    print("  from task_crawler import crawl_target")
    print("")
    print("  results = crawl_target(")
    print("      'https://target.com',")
    print("      max_depth=3,")
    print("      max_pages=50")
    print("  )")
    print("\nFeatures:")
    print("  - Recursive crawling")
    print("  - URL discovery")
    print("  - Parameter extraction")
    print("  - Form discovery")
    print("  - Same-domain filtering")


def example_xss_testing():
    """Example: XSS vulnerability testing."""
    print("\n" + "="*80)
    print("Example 7: XSS Testing")
    print("="*80 + "\n")
    
    from task_xss import test_xss_vulnerabilities
    
    print("Usage:")
    print("  from task_xss import test_xss_vulnerabilities")
    print("")
    print("  # Test reflected XSS")
    print("  results = test_xss_vulnerabilities(")
    print("      url='https://target.com/search',")
    print("      parameters=['q', 'search', 'query']")
    print("  )")
    print("")
    print("  # Test stored XSS")
    print("  results = test_xss_vulnerabilities(")
    print("      url='https://target.com/comment',")
    print("      form_data={'name': '', 'comment': '', 'email': ''}")
    print("  )")
    print("\nFeatures:")
    print("  - Reflected XSS detection")
    print("  - Stored XSS detection")
    print("  - Multiple payload types")
    print("  - Automatic confirmation")


def example_ai_analysis():
    """Example: AI-powered analysis and orchestration."""
    print("\n" + "="*80)
    print("Example 8: AI-Powered Analysis")
    print("="*80 + "\n")
    
    from task_master import analyze_scan_results, prioritize_vulnerabilities
    
    print("Usage:")
    print("  from task_master import analyze_scan_results, prioritize_vulnerabilities")
    print("")
    print("  # Analyze scan results")
    print("  analysis = analyze_scan_results(scan_results)")
    print("  ")
    print("  # Get risk level and recommendations")
    print("  print(f\"Risk Level: {analysis['risk_level']}\")")
    print("  print(f\"Priority Targets: {analysis['priority_targets']}\")")
    print("  print(f\"Recommended Actions: {analysis['recommended_actions']}\")")
    print("")
    print("  # Prioritize vulnerabilities")
    print("  prioritized = prioritize_vulnerabilities(vulnerabilities)")
    print("\nFeatures:")
    print("  - AI-powered risk assessment")
    print("  - Vulnerability prioritization")
    print("  - Action recommendations")
    print("  - Executive summary generation")


def example_environment_setup():
    """Example: Pentest environment management."""
    print("\n" + "="*80)
    print("Example 9: Environment Management")
    print("="*80 + "\n")
    
    from pentest_env import setup_environment
    
    print("Usage:")
    print("  from pentest_env import setup_environment")
    print("")
    print("  env = setup_environment('target.com')")
    print("  ")
    print("  # Save scan results")
    print("  env.save_scan_result('nmap', nmap_output)")
    print("  ")
    print("  # Save reports")
    print("  env.save_report('vulnerability_report', report_content, 'html')")
    print("  ")
    print("  # Check installed tools")
    print("  tools = env.get_installed_tools()")
    print("\nFeatures:")
    print("  - Directory structure creation")
    print("  - Scan result storage")
    print("  - Report generation")
    print("  - Tool availability checking")


def example_complete_workflow():
    """Example: Complete penetration testing workflow."""
    print("\n" + "="*80)
    print("Example 10: Complete Workflow")
    print("="*80 + "\n")
    
    print("Complete Penetration Testing Workflow:")
    print("")
    print("1. Setup Environment")
    print("   env = setup_environment('target.com')")
    print("")
    print("2. Service Reconnaissance")
    print("   services = execute_service_recon_and_vuln_scan('target.com')")
    print("")
    print("3. CVE Hunting")
    print("   for service in services['services']:")
    print("       cves = search_cve_vulnerabilities(service['name'], service['version'])")
    print("")
    print("4. Directory Brute-forcing")
    print("   dirs = execute_gobuster_scan('https://target.com')")
    print("")
    print("5. Web Crawling")
    print("   crawl_data = crawl_target('https://target.com')")
    print("")
    print("6. Vulnerability Testing")
    print("   xss_results = test_xss_vulnerabilities(url, parameters)")
    print("")
    print("7. AI Analysis")
    print("   analysis = analyze_scan_results(all_results)")
    print("   prioritized = prioritize_vulnerabilities(vulnerabilities)")
    print("")
    print("8. Generate Reports")
    print("   env.save_report('final_report', report_content, 'html')")


def main():
    """Run all examples."""
    print("\n" + "="*80)
    print("🎓 DBMS Security Scanning System - Usage Examples")
    print("="*80)
    
    examples = [
        ("Service Reconnaissance", example_service_scan),
        ("Gobuster Directory Scanning", example_gobuster_scan),
        ("CVE Hunting", example_cve_hunting),
        ("Nuclei Template Generation", example_nuclei_generation),
        ("Reconnaissance Engine", example_recon_engine),
        ("Web Crawling", example_web_crawling),
        ("XSS Testing", example_xss_testing),
        ("AI-Powered Analysis", example_ai_analysis),
        ("Environment Management", example_environment_setup),
        ("Complete Workflow", example_complete_workflow),
    ]
    
    for i, (name, example_func) in enumerate(examples, 1):
        example_func()
        
    print("\n" + "="*80)
    print("📚 For More Information")
    print("="*80)
    print("\nSee README.md for detailed documentation")
    print("See test_system.py for functional tests")
    print("See requirements.txt for dependencies")
    print("\n" + "="*80 + "\n")


if __name__ == '__main__':
    main()
