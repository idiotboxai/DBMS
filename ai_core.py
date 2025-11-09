# ai_core.py
"""
AI Core utilities for command execution and AI interactions.
"""

import subprocess
import requests
import json
from typing import List, Dict, Any, Optional
from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, REQUEST_TIMEOUT, REQUEST_USER_AGENT


class AICore:
    """Core utilities for command execution and system interactions."""
    
    @staticmethod
    def run_command(command: List[str], timeout: int = 300) -> Optional[str]:
        """
        Execute a system command and return its output.
        
        Args:
            command: List of command arguments
            timeout: Command timeout in seconds
            
        Returns:
            Command output as string, or None if failed
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            # Return stdout if available, otherwise stderr
            if result.stdout:
                return result.stdout
            elif result.stderr:
                return result.stderr
            return None
            
        except subprocess.TimeoutExpired:
            print(f"[ERROR] Command timed out after {timeout}s: {' '.join(command)}")
            return None
        except FileNotFoundError:
            print(f"[ERROR] Command not found: {command[0]}")
            return None
        except Exception as e:
            print(f"[ERROR] Command execution failed: {str(e)}")
            return None


def ask_ollama(prompt: str, model: str = None, json_mode: bool = True) -> Optional[Dict[str, Any]]:
    """
    Send a prompt to Ollama and get a response.
    
    Args:
        prompt: The prompt to send
        model: Model to use (defaults to config value)
        json_mode: Whether to expect JSON response
        
    Returns:
        Parsed JSON response or None if failed
    """
    if model is None:
        model = OLLAMA_MODEL
        
    try:
        url = f"{OLLAMA_BASE_URL}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json" if json_mode else None
        }
        
        response = requests.post(
            url,
            json=payload,
            timeout=OLLAMA_TIMEOUT
        )
        
        if response.status_code != 200:
            print(f"[OLLAMA] Error: Status {response.status_code}")
            return None
            
        result = response.json()
        response_text = result.get("response", "")
        
        if json_mode:
            try:
                # Try to parse as JSON
                return json.loads(response_text)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                if "```json" in response_text:
                    json_start = response_text.find("```json") + 7
                    json_end = response_text.find("```", json_start)
                    json_text = response_text[json_start:json_end].strip()
                    return json.loads(json_text)
                elif "```" in response_text:
                    json_start = response_text.find("```") + 3
                    json_end = response_text.find("```", json_start)
                    json_text = response_text[json_start:json_end].strip()
                    return json.loads(json_text)
                else:
                    print(f"[OLLAMA] Failed to parse JSON: {response_text[:100]}")
                    return None
        else:
            return {"response": response_text}
            
    except requests.exceptions.Timeout:
        print(f"[OLLAMA] Request timed out after {OLLAMA_TIMEOUT}s")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[OLLAMA] Connection failed. Is Ollama running at {OLLAMA_BASE_URL}?")
        return None
    except Exception as e:
        print(f"[OLLAMA] Error: {str(e)}")
        return None


def perform_web_search(query: str, num_results: int = 5) -> List[Dict[str, str]]:
    """
    Perform a web search using DuckDuckGo HTML interface.
    
    Args:
        query: Search query
        num_results: Maximum number of results to return
        
    Returns:
        List of search results with 'title', 'url', 'snippet'
    """
    try:
        import re
        from urllib.parse import quote_plus
        
        # DuckDuckGo HTML search
        search_url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        headers = {
            "User-Agent": REQUEST_USER_AGENT
        }
        
        response = requests.get(search_url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code != 200:
            print(f"[SEARCH] Error: Status {response.status_code}")
            return []
            
        html = response.text
        results = []
        
        # Parse results using regex (simple approach)
        # Look for result blocks
        result_pattern = r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([^<]+)</a>'
        snippet_pattern = r'<a[^>]+class="result__snippet"[^>]*>([^<]+)</a>'
        
        url_matches = re.findall(result_pattern, html)
        snippet_matches = re.findall(snippet_pattern, html)
        
        for i, (url, title) in enumerate(url_matches[:num_results]):
            snippet = snippet_matches[i] if i < len(snippet_matches) else ""
            results.append({
                "title": title.strip(),
                "url": url.strip(),
                "snippet": snippet.strip()
            })
            
        return results
        
    except Exception as e:
        print(f"[SEARCH] Error: {str(e)}")
        return []


def get_with_retry(url: str, headers: Dict[str, str] = None, 
                   proxies: Dict[str, str] = None, timeout: int = None,
                   max_retries: int = 3) -> Optional[requests.Response]:
    """
    Perform HTTP GET with retry logic.
    
    Args:
        url: URL to fetch
        headers: Optional headers
        proxies: Optional proxy configuration
        timeout: Request timeout
        max_retries: Maximum number of retries
        
    Returns:
        Response object or None if failed
    """
    if timeout is None:
        timeout = REQUEST_TIMEOUT
        
    if headers is None:
        headers = {"User-Agent": REQUEST_USER_AGENT}
    elif "User-Agent" not in headers:
        headers["User-Agent"] = REQUEST_USER_AGENT
        
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                headers=headers,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=True
            )
            return response
            
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                print(f"[RETRY] Timeout, attempt {attempt + 1}/{max_retries}")
                continue
            print(f"[ERROR] Request timed out after {max_retries} attempts")
            return None
            
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                print(f"[RETRY] Connection error, attempt {attempt + 1}/{max_retries}")
                continue
            print(f"[ERROR] Connection failed after {max_retries} attempts")
            return None
            
        except Exception as e:
            print(f"[ERROR] Request failed: {str(e)}")
            return None
            
    return None


def post_with_retry(url: str, data: Any = None, json_data: Dict = None,
                    headers: Dict[str, str] = None, proxies: Dict[str, str] = None,
                    timeout: int = None, max_retries: int = 3) -> Optional[requests.Response]:
    """
    Perform HTTP POST with retry logic.
    
    Args:
        url: URL to post to
        data: Form data
        json_data: JSON data
        headers: Optional headers
        proxies: Optional proxy configuration
        timeout: Request timeout
        max_retries: Maximum number of retries
        
    Returns:
        Response object or None if failed
    """
    if timeout is None:
        timeout = REQUEST_TIMEOUT
        
    if headers is None:
        headers = {"User-Agent": REQUEST_USER_AGENT}
    elif "User-Agent" not in headers:
        headers["User-Agent"] = REQUEST_USER_AGENT
        
    for attempt in range(max_retries):
        try:
            response = requests.post(
                url,
                data=data,
                json=json_data,
                headers=headers,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=True
            )
            return response
            
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                print(f"[RETRY] Timeout, attempt {attempt + 1}/{max_retries}")
                continue
            print(f"[ERROR] Request timed out after {max_retries} attempts")
            return None
            
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                print(f"[RETRY] Connection error, attempt {attempt + 1}/{max_retries}")
                continue
            print(f"[ERROR] Connection failed after {max_retries} attempts")
            return None
            
        except Exception as e:
            print(f"[ERROR] Request failed: {str(e)}")
            return None
            
    return None
