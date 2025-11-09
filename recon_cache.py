# recon_cache.py
"""
Database caching for reconnaissance results.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from config import DB_PATH, CVE_CACHE_EXPIRY_DAYS, SEARCH_CACHE_EXPIRY_DAYS, RECON_DIR


class ReconCache:
    """Database cache for reconnaissance and vulnerability data."""
    
    def __init__(self, db_path: str = None):
        """Initialize the cache database."""
        if db_path is None:
            db_path = DB_PATH
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.db_path = db_path
        self.conn = None
        self._initialize_db()
        
    def _initialize_db(self):
        """Create database tables if they don't exist."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            cursor = self.conn.cursor()
            
            # CVE cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT NOT NULL
                )
            """)
            
            # Search results cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS search_cache (
                    query_hash TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    results TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT NOT NULL
                )
            """)
            
            # Subdomain cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subdomain_cache (
                    domain TEXT PRIMARY KEY,
                    subdomains TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT NOT NULL
                )
            """)
            
            # Service fingerprint cache
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS service_cache (
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service_data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (host, port)
                )
            """)
            
            # Nuclei template cache
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS template_cache (
                    template_id TEXT PRIMARY KEY,
                    template_content TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            
            self.conn.commit()
            
        except Exception as e:
            print(f"[CACHE] Database initialization error: {str(e)}")
            
    def cache_cve(self, cve_id: str, data: Dict[str, Any]) -> bool:
        """
        Cache CVE data.
        
        Args:
            cve_id: CVE identifier
            data: CVE data dictionary
            
        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO cve_cache (cve_id, data, created_at, last_accessed)
                VALUES (?, ?, ?, ?)
            """, (cve_id, json.dumps(data), now, now))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"[CACHE] Error caching CVE {cve_id}: {str(e)}")
            return False
            
    def get_cached_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached CVE data if not expired.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVE data dictionary or None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT data, created_at FROM cve_cache WHERE cve_id = ?
            """, (cve_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            data_json, created_at = row
            created = datetime.fromisoformat(created_at)
            expiry = created + timedelta(days=CVE_CACHE_EXPIRY_DAYS)
            
            # Check if expired
            if datetime.now() > expiry:
                print(f"[CACHE] Expired entry for {cve_id}")
                return None
                
            # Update last accessed time
            cursor.execute("""
                UPDATE cve_cache SET last_accessed = ? WHERE cve_id = ?
            """, (datetime.now().isoformat(), cve_id))
            self.conn.commit()
            
            return json.loads(data_json)
            
        except Exception as e:
            print(f"[CACHE] Error retrieving CVE {cve_id}: {str(e)}")
            return None
            
    def cache_search_results(self, query: str, results: List[Dict[str, Any]]) -> bool:
        """
        Cache search results.
        
        Args:
            query: Search query
            results: List of search results
            
        Returns:
            True if successful
        """
        try:
            import hashlib
            
            # Create hash of query for indexing
            query_hash = hashlib.sha256(query.encode()).hexdigest()
            
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO search_cache (query_hash, query, results, created_at, last_accessed)
                VALUES (?, ?, ?, ?, ?)
            """, (query_hash, query, json.dumps(results), now, now))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"[CACHE] Error caching search results: {str(e)}")
            return False
            
    def get_cached_search(self, query: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get cached search results if not expired.
        
        Args:
            query: Search query
            
        Returns:
            List of search results or None
        """
        try:
            import hashlib
            
            query_hash = hashlib.sha256(query.encode()).hexdigest()
            
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT results, created_at FROM search_cache WHERE query_hash = ?
            """, (query_hash,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            results_json, created_at = row
            created = datetime.fromisoformat(created_at)
            expiry = created + timedelta(days=SEARCH_CACHE_EXPIRY_DAYS)
            
            # Check if expired
            if datetime.now() > expiry:
                print(f"[CACHE] Expired search results for query")
                return None
                
            # Update last accessed time
            cursor.execute("""
                UPDATE search_cache SET last_accessed = ? WHERE query_hash = ?
            """, (datetime.now().isoformat(), query_hash))
            self.conn.commit()
            
            return json.loads(results_json)
            
        except Exception as e:
            print(f"[CACHE] Error retrieving search results: {str(e)}")
            return None
            
    def cache_subdomains(self, domain: str, subdomains: List[str]) -> bool:
        """
        Cache discovered subdomains.
        
        Args:
            domain: Base domain
            subdomains: List of subdomains
            
        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO subdomain_cache (domain, subdomains, created_at, last_accessed)
                VALUES (?, ?, ?, ?)
            """, (domain, json.dumps(subdomains), now, now))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"[CACHE] Error caching subdomains: {str(e)}")
            return False
            
    def get_cached_subdomains(self, domain: str) -> Optional[List[str]]:
        """
        Get cached subdomains.
        
        Args:
            domain: Base domain
            
        Returns:
            List of subdomains or None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT subdomains FROM subdomain_cache WHERE domain = ?
            """, (domain,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            # Update last accessed time
            cursor.execute("""
                UPDATE subdomain_cache SET last_accessed = ? WHERE domain = ?
            """, (datetime.now().isoformat(), domain))
            self.conn.commit()
            
            return json.loads(row[0])
            
        except Exception as e:
            print(f"[CACHE] Error retrieving subdomains: {str(e)}")
            return None
            
    def cache_service(self, host: str, port: int, service_data: Dict[str, Any]) -> bool:
        """
        Cache service fingerprint data.
        
        Args:
            host: Target host
            port: Port number
            service_data: Service information
            
        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO service_cache (host, port, service_data, created_at)
                VALUES (?, ?, ?, ?)
            """, (host, port, json.dumps(service_data), now))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"[CACHE] Error caching service: {str(e)}")
            return False
            
    def get_cached_service(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Get cached service data.
        
        Args:
            host: Target host
            port: Port number
            
        Returns:
            Service data dictionary or None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT service_data FROM service_cache WHERE host = ? AND port = ?
            """, (host, port))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            return json.loads(row[0])
            
        except Exception as e:
            print(f"[CACHE] Error retrieving service: {str(e)}")
            return None
            
    def cache_template(self, template_id: str, template_content: str, 
                      metadata: Dict[str, Any]) -> bool:
        """
        Cache Nuclei template.
        
        Args:
            template_id: Template identifier
            template_content: Template YAML content
            metadata: Template metadata
            
        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO template_cache (template_id, template_content, metadata, created_at)
                VALUES (?, ?, ?, ?)
            """, (template_id, template_content, json.dumps(metadata), now))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"[CACHE] Error caching template: {str(e)}")
            return False
            
    def get_cached_template(self, template_id: str) -> Optional[tuple]:
        """
        Get cached template.
        
        Args:
            template_id: Template identifier
            
        Returns:
            Tuple of (template_content, metadata) or None
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT template_content, metadata FROM template_cache WHERE template_id = ?
            """, (template_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            template_content, metadata_json = row
            return (template_content, json.loads(metadata_json))
            
        except Exception as e:
            print(f"[CACHE] Error retrieving template: {str(e)}")
            return None
            
    def cleanup_expired(self):
        """Remove expired cache entries."""
        try:
            cursor = self.conn.cursor()
            
            # Clean up expired CVE cache
            cve_expiry = (datetime.now() - timedelta(days=CVE_CACHE_EXPIRY_DAYS)).isoformat()
            cursor.execute("""
                DELETE FROM cve_cache WHERE created_at < ?
            """, (cve_expiry,))
            
            # Clean up expired search cache
            search_expiry = (datetime.now() - timedelta(days=SEARCH_CACHE_EXPIRY_DAYS)).isoformat()
            cursor.execute("""
                DELETE FROM search_cache WHERE created_at < ?
            """, (search_expiry,))
            
            self.conn.commit()
            print(f"[CACHE] Cleaned up expired entries")
            
        except Exception as e:
            print(f"[CACHE] Error during cleanup: {str(e)}")
            
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None


# Global cache instance
_cache_instance = None

def get_cache() -> ReconCache:
    """Get or create global cache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = ReconCache()
    return _cache_instance
