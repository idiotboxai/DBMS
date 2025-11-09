# recon_engine.py
"""
Main reconnaissance engine with subdomain filtering and orchestration.
"""

import re
from typing import List, Set, Optional
from urllib.parse import urlparse
from config import FILTER_SUBDOMAINS


def filter_subdomains(discovered_subdomains: List[str], input_domains: List[str]) -> List[str]:
    """
    Filter discovered subdomains to ensure they match input domains.
    
    Args:
        discovered_subdomains: List of discovered subdomains
        input_domains: List of input domains to filter against
        
    Returns:
        Filtered list of subdomains
    """
    if not FILTER_SUBDOMAINS:
        return discovered_subdomains
        
    print(f"\n[SUBDOMAIN_FILTER] Filtering {len(discovered_subdomains)} subdomains")
    
    # Normalize input domains
    normalized_input = set()
    for domain in input_domains:
        # Remove protocol and path
        parsed = urlparse(domain if '://' in domain else f'http://{domain}')
        domain_only = parsed.netloc or parsed.path
        # Remove port if present
        domain_only = domain_only.split(':')[0].lower()
        normalized_input.add(domain_only)
        
    filtered = []
    
    for subdomain in discovered_subdomains:
        # Normalize subdomain
        parsed = urlparse(subdomain if '://' in subdomain else f'http://{subdomain}')
        sub_domain = parsed.netloc or parsed.path
        sub_domain = sub_domain.split(':')[0].lower()
        
        # Check if subdomain matches any input domain
        is_valid = False
        for input_domain in normalized_input:
            # Check if it's the same domain or a subdomain of input
            if sub_domain == input_domain or sub_domain.endswith(f'.{input_domain}'):
                is_valid = True
                break
                
        if is_valid:
            filtered.append(subdomain)
        else:
            print(f"[SUBDOMAIN_FILTER] Rejected: {subdomain} (not in scope)")
            
    print(f"[SUBDOMAIN_FILTER] ✅ Kept {len(filtered)} valid subdomains")
    
    return filtered


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.
    
    Args:
        url: URL string
        
    Returns:
        Domain or None
    """
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        domain = parsed.netloc or parsed.path
        domain = domain.split(':')[0].lower()
        return domain if domain else None
    except:
        return None


def is_subdomain_of(subdomain: str, parent_domain: str) -> bool:
    """
    Check if subdomain is a subdomain of parent domain.
    
    Args:
        subdomain: Subdomain to check
        parent_domain: Parent domain
        
    Returns:
        True if subdomain is valid subdomain of parent
    """
    sub = extract_domain_from_url(subdomain)
    parent = extract_domain_from_url(parent_domain)
    
    if not sub or not parent:
        return False
        
    return sub == parent or sub.endswith(f'.{parent}')


def deduplicate_targets(targets: List[str]) -> List[str]:
    """
    Remove duplicate targets while preserving order.
    
    Args:
        targets: List of target URLs/domains
        
    Returns:
        Deduplicated list
    """
    seen = set()
    result = []
    
    for target in targets:
        # Normalize for comparison
        normalized = extract_domain_from_url(target)
        
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(target)
            
    return result


class ReconEngine:
    """Main reconnaissance orchestration engine."""
    
    def __init__(self, input_domains: List[str]):
        """
        Initialize recon engine.
        
        Args:
            input_domains: List of target domains
        """
        self.input_domains = input_domains
        self.discovered_subdomains = []
        self.discovered_services = []
        self.discovered_vulnerabilities = []
        
    def add_subdomains(self, subdomains: List[str]):
        """
        Add discovered subdomains with filtering.
        
        Args:
            subdomains: List of discovered subdomains
        """
        # Filter subdomains
        filtered = filter_subdomains(subdomains, self.input_domains)
        
        # Add to discovered list
        self.discovered_subdomains.extend(filtered)
        
        # Deduplicate
        self.discovered_subdomains = deduplicate_targets(self.discovered_subdomains)
        
    def add_services(self, services: List[dict]):
        """
        Add discovered services.
        
        Args:
            services: List of service dictionaries
        """
        self.discovered_services.extend(services)
        
    def add_vulnerabilities(self, vulnerabilities: List[dict]):
        """
        Add discovered vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        """
        self.discovered_vulnerabilities.extend(vulnerabilities)
        
    def get_summary(self) -> dict:
        """
        Get reconnaissance summary.
        
        Returns:
            Summary dictionary
        """
        return {
            'input_domains': self.input_domains,
            'subdomain_count': len(self.discovered_subdomains),
            'service_count': len(self.discovered_services),
            'vulnerability_count': len(self.discovered_vulnerabilities),
            'subdomains': self.discovered_subdomains,
            'services': self.discovered_services,
            'vulnerabilities': self.discovered_vulnerabilities
        }
        
    def print_summary(self):
        """Print reconnaissance summary."""
        summary = self.get_summary()
        
        print(f"\n{'='*80}")
        print(f"📊 RECONNAISSANCE SUMMARY")
        print(f"{'='*80}")
        print(f"Input Domains: {len(summary['input_domains'])}")
        print(f"Discovered Subdomains: {summary['subdomain_count']}")
        print(f"Discovered Services: {summary['service_count']}")
        print(f"Discovered Vulnerabilities: {summary['vulnerability_count']}")
        print(f"{'='*80}\n")
