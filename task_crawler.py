# task_crawler.py
"""
Web crawler for discovering endpoints and parameters.
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set, List, Dict, Optional
from ai_core import get_with_retry
from config import REQUEST_USER_AGENT

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("[WARNING] BeautifulSoup4 not installed. Install with: pip install beautifulsoup4")


class WebCrawler:
    """Web crawler for endpoint discovery."""
    
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 50):
        """
        Initialize crawler.
        
        Args:
            base_url: Base URL to crawl
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
        """
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.discovered_urls = set()
        self.discovered_params = set()
        self.discovered_forms = []
        
    def crawl(self) -> Dict[str, any]:
        """
        Start crawling.
        
        Returns:
            Dictionary with discovered data
        """
        if not BS4_AVAILABLE:
            print(f"\n[CRAWLER] ❌ BeautifulSoup4 not available. Cannot crawl.")
            return {
                'urls': [],
                'parameters': [],
                'forms': []
            }
            
        print(f"\n[CRAWLER] Starting crawl of {self.base_url}")
        
        self._crawl_recursive(self.base_url, 0)
        
        print(f"[CRAWLER] ✅ Discovered {len(self.discovered_urls)} URLs")
        print(f"[CRAWLER] ✅ Discovered {len(self.discovered_params)} parameters")
        print(f"[CRAWLER] ✅ Discovered {len(self.discovered_forms)} forms")
        
        return {
            'urls': list(self.discovered_urls),
            'parameters': list(self.discovered_params),
            'forms': self.discovered_forms
        }
        
    def _crawl_recursive(self, url: str, depth: int):
        """Recursive crawl implementation."""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
            
        if url in self.visited:
            return
            
        self.visited.add(url)
        
        try:
            response = get_with_retry(url, timeout=10)
            
            if not response or response.status_code != 200:
                return
                
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return
                
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract parameters from URL
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    self.discovered_params.add(param_name)
                    
            # Find links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                # Only crawl same domain
                if self._is_same_domain(full_url):
                    self.discovered_urls.add(full_url)
                    self._crawl_recursive(full_url, depth + 1)
                    
            # Find forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name', '')
                    if input_name:
                        form_data['inputs'].append({
                            'name': input_name,
                            'type': input_tag.get('type', 'text')
                        })
                        self.discovered_params.add(input_name)
                        
                self.discovered_forms.append(form_data)
                
        except Exception as e:
            print(f"[CRAWLER] Error crawling {url}: {str(e)[:50]}")
            
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is same domain as base."""
        base_domain = urlparse(self.base_url).netloc
        url_domain = urlparse(url).netloc
        return base_domain == url_domain


def crawl_target(target_url: str, max_depth: int = 3, max_pages: int = 50) -> Dict[str, any]:
    """
    Crawl a target URL.
    
    Args:
        target_url: Target URL to crawl
        max_depth: Maximum crawl depth
        max_pages: Maximum pages to crawl
        
    Returns:
        Crawl results dictionary
    """
    crawler = WebCrawler(target_url, max_depth, max_pages)
    return crawler.crawl()
