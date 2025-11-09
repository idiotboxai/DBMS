# cve_hunter.py
"""
CVE vulnerability hunter with multiple search engines and caching.
"""

import re
import requests
from typing import List, Dict, Optional, Any
from datetime import datetime
from ai_core import perform_web_search, ask_ollama, get_with_retry
from config import GITHUB_API_TOKEN, FAKE_AUTHORS, REQUEST_USER_AGENT
from recon_cache import get_cache
from nuclei_generator import NucleiGenerator, TemplateValidator


class CVEHunter:
    """Main CVE hunting and template collection class."""
    
    def __init__(self):
        self.cache = get_cache()
        self.generator = NucleiGenerator()
        self.validator = TemplateValidator()
        
    def search_cve(self, cve_id: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Search for CVE information from multiple sources.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            use_cache: Whether to use cached results
            
        Returns:
            Dict with CVE information
        """
        print(f"\n[CVE_HUNTER] Searching for {cve_id}")
        
        # Check cache first
        if use_cache:
            cached = self.cache.get_cached_cve(cve_id)
            if cached:
                print(f"[CVE_HUNTER] ✅ Using cached data")
                return cached
                
        # Search from multiple sources
        results = {
            'cve_id': cve_id,
            'description': '',
            'severity': 'unknown',
            'cvss_score': 0.0,
            'references': [],
            'pocs': [],
            'nuclei_templates': []
        }
        
        # 1. Search NVD
        nvd_data = self._search_nvd(cve_id)
        if nvd_data:
            results.update(nvd_data)
            
        # 2. Search DuckDuckGo for additional context
        ddg_results = self._search_duckduckgo(cve_id)
        if ddg_results:
            results['references'].extend(ddg_results)
            
        # 3. Search PacketStorm for POCs
        ps_pocs = self._search_packetstorm(cve_id)
        if ps_pocs:
            results['pocs'].extend(ps_pocs)
            
        # 4. Search GitHub for POCs
        gh_pocs = self._search_github(cve_id)
        if gh_pocs:
            results['pocs'].extend(gh_pocs)
            
        # 5. Search for existing Nuclei templates
        templates = self._search_nuclei_templates(cve_id)
        if templates:
            results['nuclei_templates'].extend(templates)
            
        # Cache results
        self.cache.cache_cve(cve_id, results)
        
        print(f"[CVE_HUNTER] ✅ Found: {len(results['pocs'])} POCs, {len(results['nuclei_templates'])} templates")
        
        return results
        
    def _search_nvd(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Search NVD (National Vulnerability Database) for CVE info.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVE data dict or None
        """
        print(f"[NVD] Searching for {cve_id}")
        
        try:
            # NVD API v2
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {
                'User-Agent': REQUEST_USER_AGENT
            }
            
            response = get_with_retry(url, headers=headers, timeout=15)
            
            if not response or response.status_code != 200:
                print(f"[NVD] ❌ Failed: {response.status_code if response else 'No response'}")
                return None
                
            data = response.json()
            
            if 'vulnerabilities' not in data or len(data['vulnerabilities']) == 0:
                print(f"[NVD] ❌ No data found")
                return None
                
            vuln = data['vulnerabilities'][0]['cve']
            
            # Extract description
            descriptions = vuln.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
                    
            # Extract CVSS score
            metrics = vuln.get('metrics', {})
            cvss_score = 0.0
            severity = 'unknown'
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'unknown').lower()
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                
            # Extract references
            references = []
            for ref in vuln.get('references', []):
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('source', '')
                })
                
            print(f"[NVD] ✅ Found: {severity.upper()} (CVSS: {cvss_score})")
            
            return {
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'references': references
            }
            
        except Exception as e:
            print(f"[NVD] ❌ Error: {str(e)}")
            return None
            
    def _search_duckduckgo(self, cve_id: str) -> List[Dict[str, str]]:
        """Search DuckDuckGo for CVE information."""
        print(f"[DUCKDUCKGO] Searching for {cve_id}")
        
        # Check search cache
        query = f"{cve_id} vulnerability exploit"
        cached_results = self.cache.get_cached_search(query)
        
        if cached_results:
            print(f"[DUCKDUCKGO] ✅ Using cached results")
            return cached_results
            
        # Perform search
        results = perform_web_search(query, num_results=10)
        
        # Cache results
        self.cache.cache_search_results(query, results)
        
        print(f"[DUCKDUCKGO] ✅ Found {len(results)} results")
        return results
        
    def _search_packetstorm(self, cve_id: str) -> List[Dict[str, str]]:
        """Search PacketStorm Security for POCs."""
        print(f"[PACKETSTORM] Searching for {cve_id}")
        
        try:
            url = f"https://packetstormsecurity.com/files/cve/{cve_id}"
            headers = {'User-Agent': REQUEST_USER_AGENT}
            
            response = get_with_retry(url, headers=headers, timeout=15)
            
            if not response or response.status_code != 200:
                print(f"[PACKETSTORM] ❌ No results")
                return []
                
            html = response.text
            
            # Extract POC links
            pocs = []
            
            # Look for GitHub links
            github_pattern = r'href="(https://github\.com/[^"]+)"'
            github_links = re.findall(github_pattern, html)
            
            for link in set(github_links[:5]):
                pocs.append({
                    'type': 'github',
                    'url': link,
                    'source': 'PacketStorm'
                })
                
            # Look for exploit DB links
            edb_pattern = r'href="(https://www\.exploit-db\.com/exploits/\d+)"'
            edb_links = re.findall(edb_pattern, html)
            
            for link in set(edb_links[:5]):
                pocs.append({
                    'type': 'exploit-db',
                    'url': link,
                    'source': 'PacketStorm'
                })
                
            print(f"[PACKETSTORM] ✅ Found {len(pocs)} POCs")
            return pocs
            
        except Exception as e:
            print(f"[PACKETSTORM] ❌ Error: {str(e)}")
            return []
            
    def _search_github(self, cve_id: str) -> List[Dict[str, str]]:
        """Search GitHub for POC repositories."""
        print(f"[GITHUB] Searching for {cve_id}")
        
        if not GITHUB_API_TOKEN:
            print(f"[GITHUB] ⚠️ No API token configured")
            return []
            
        try:
            query = f"{cve_id} POC"
            url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc&per_page=10"
            
            headers = {
                'Authorization': f'token {GITHUB_API_TOKEN}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': REQUEST_USER_AGENT
            }
            
            response = get_with_retry(url, headers=headers, timeout=15)
            
            if not response or response.status_code != 200:
                print(f"[GITHUB] ❌ Search failed")
                return []
                
            data = response.json()
            items = data.get('items', [])
            
            pocs = []
            for repo in items:
                # Filter out low-quality repos
                stars = repo.get('stargazers_count', 0)
                if stars < 3:
                    continue
                    
                pocs.append({
                    'type': 'github',
                    'url': repo.get('html_url', ''),
                    'source': 'GitHub API',
                    'stars': stars,
                    'description': repo.get('description', '')[:200]
                })
                
            print(f"[GITHUB] ✅ Found {len(pocs)} POCs")
            return pocs
            
        except Exception as e:
            print(f"[GITHUB] ❌ Error: {str(e)}")
            return []
            
    def _search_nuclei_templates(self, cve_id: str) -> List[Dict[str, str]]:
        """
        Search for existing Nuclei templates.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of template info dicts
        """
        print(f"[NUCLEI] Searching for templates for {cve_id}")
        
        templates = []
        
        # Search GitHub for official projectdiscovery templates
        if GITHUB_API_TOKEN:
            try:
                query = f"{cve_id} repo:projectdiscovery/nuclei-templates"
                url = f"https://api.github.com/search/code?q={query}&per_page=5"
                
                headers = {
                    'Authorization': f'token {GITHUB_API_TOKEN}',
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': REQUEST_USER_AGENT
                }
                
                response = get_with_retry(url, headers=headers, timeout=15)
                
                if response and response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    
                    for item in items:
                        # Get template content
                        download_url = item.get('html_url', '').replace('/blob/', '/raw/')
                        
                        templates.append({
                            'source': 'projectdiscovery',
                            'url': item.get('html_url', ''),
                            'download_url': download_url,
                            'path': item.get('path', ''),
                            'official': True
                        })
                        
                    print(f"[NUCLEI] ✅ Found {len(templates)} official templates")
                    
            except Exception as e:
                print(f"[NUCLEI] ⚠️ GitHub search error: {str(e)}")
                
        return templates
        
    def filter_templates(self, templates: List[str]) -> List[str]:
        """
        Filter out AI-generated and low-quality templates.
        
        Args:
            templates: List of template YAML strings
            
        Returns:
            Filtered list of templates
        """
        print(f"[FILTER] Filtering {len(templates)} templates")
        
        filtered = []
        
        for template in templates:
            # Check for fake authors
            if self.validator.is_fake_author(template):
                print(f"[FILTER] ❌ Rejected: Fake author")
                continue
                
            # Validate YAML structure
            if not self.validator.validate_yaml_structure(template):
                print(f"[FILTER] ❌ Rejected: Invalid structure")
                continue
                
            filtered.append(template)
            
        print(f"[FILTER] ✅ {len(filtered)} templates passed filtering")
        return filtered
        
    def select_best_template_with_ai(self, templates: List[str], 
                                    cve_description: str) -> Optional[str]:
        """
        Use AI to select the best template from multiple options.
        
        Args:
            templates: List of template YAML strings
            cve_description: CVE description for context
            
        Returns:
            Best template or None
        """
        # Filter first
        valid_templates = self.filter_templates(templates)
        
        if not valid_templates:
            print(f"[AI_SELECT] ❌ No valid templates to select from")
            return None
            
        # Use generator's selection method
        return self.generator.select_best_template(valid_templates, cve_description)
        
    def hunt_vulnerabilities(self, service_name: str, version: str,
                            generate_templates: bool = False) -> Dict[str, Any]:
        """
        Hunt for vulnerabilities affecting a specific service.
        
        Args:
            service_name: Service name (e.g., 'Apache')
            version: Service version
            generate_templates: Whether to generate new templates
            
        Returns:
            Dict with vulnerability information
        """
        print(f"\n{'='*80}")
        print(f"🔍 CVE HUNTING")
        print(f"Target: {service_name} {version}")
        print(f"{'='*80}\n")
        
        # Search for CVEs related to the service
        search_query = f"{service_name} {version} CVE vulnerability"
        
        # Check cache first
        cached_results = self.cache.get_cached_search(search_query)
        
        if cached_results:
            print(f"[HUNT] ✅ Using cached search results")
            search_results = cached_results
        else:
            search_results = perform_web_search(search_query, num_results=20)
            self.cache.cache_search_results(search_query, search_results)
            
        # Extract CVE IDs from search results
        cve_ids = set()
        for result in search_results:
            # Look for CVE patterns in title, URL, and snippet
            text = f"{result.get('title', '')} {result.get('url', '')} {result.get('snippet', '')}"
            found_cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
            cve_ids.update([cve.upper() for cve in found_cves])
            
        print(f"[HUNT] Found {len(cve_ids)} unique CVEs")
        
        # Search each CVE
        vulnerabilities = []
        for cve_id in sorted(cve_ids)[:10]:  # Limit to 10 CVEs
            cve_data = self.search_cve(cve_id)
            
            if cve_data:
                vulnerabilities.append(cve_data)
                
                # Generate template if requested and no template exists
                if generate_templates and len(cve_data.get('nuclei_templates', [])) == 0:
                    if cve_data.get('pocs'):
                        print(f"[HUNT] Generating template for {cve_id}")
                        # This would use the generator with POC context
                        # Implementation depends on having POC code available
                        
        results = {
            'service': service_name,
            'version': version,
            'cve_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'critical_count': sum(1 for v in vulnerabilities if v.get('severity') == 'critical'),
            'high_count': sum(1 for v in vulnerabilities if v.get('severity') == 'high'),
        }
        
        print(f"\n{'='*80}")
        print(f"✅ HUNTING COMPLETE")
        print(f"Total CVEs: {results['cve_count']}")
        print(f"Critical: {results['critical_count']}")
        print(f"High: {results['high_count']}")
        print(f"{'='*80}\n")
        
        return results


def search_cve_vulnerabilities(service_name: str, version: str,
                               generate_templates: bool = False) -> Dict[str, Any]:
    """
    Main entry point for CVE hunting.
    
    Args:
        service_name: Service name
        version: Service version
        generate_templates: Whether to generate Nuclei templates
        
    Returns:
        Vulnerability search results
    """
    hunter = CVEHunter()
    return hunter.hunt_vulnerabilities(service_name, version, generate_templates)


def get_cve_info(cve_id: str) -> Dict[str, Any]:
    """
    Get information about a specific CVE.
    
    Args:
        cve_id: CVE identifier
        
    Returns:
        CVE information dict
    """
    hunter = CVEHunter()
    return hunter.search_cve(cve_id)
