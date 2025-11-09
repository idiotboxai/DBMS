#task_recon_services.py
import re
import os
import json
import requests
from urllib.parse import urlparse
from ai_core import AICore, perform_web_search, ask_ollama
from config import NMAP_PORTS, GITHUB_API_TOKEN
from git_analyzer import clone_and_analyze_repo
import shutil
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def _run_naabu(target, top_ports=1000, rate=1000):
    """
    Run Naabu for fast initial port discovery.
    Returns list of open ports.
    """
    try:
        command = ['naabu', '-host', target, '-top-ports', str(top_ports), '-rate', str(rate), '-silent', '-json']
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return []
        ports = []
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                if 'port' in data:
                    ports.append(str(data['port']))
            except json.JSONDecodeError:
                continue
        return ports
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return []

def _get_final_url(url, timeout=10):
    """
    Follow redirects and get final URL.
    Returns tuple: (final_url, redirect_chain)
    """
    try:
        session = requests.Session()
        session.max_redirects = 10
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        redirect_chain = [resp.url for resp in response.history]
        redirect_chain.append(response.url)
        return response.url, redirect_chain
    except Exception:
        return url, [url]

def _filter_critical_cves(cve_list, max_cves=5):
    """
    Filter and prioritize CVEs by CVSS score.
    Only return HIGH/CRITICAL vulnerabilities (CVSS >= 7.0)
    """
    critical_cves = []
    
    for cve_id in cve_list:
        # Extract year from CVE (CVE-YYYY-XXXXX)
        try:
            year = int(cve_id.split('-')[1])
            # Prioritize recent CVEs (last 5 years)
            if year >= 2019:
                critical_cves.append(cve_id)
        except:
            continue
    
    # Return top N most recent CVEs
    return critical_cves[:max_cves]

def _fetch_cve_from_packetstorm(cve_id):
    """
    Fetch POC information from PacketStorm for a given CVE.
    Returns links to GitHub POCs or external exploit code.
    """
    print(f"[PACKETSTORM] Checking {cve_id}...")
    try:
        # FIXED: Correct URL
        url = f"https://packetstormsecurity.com/files/cve/{cve_id}"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return []
        
        html = response.text
        
        # Look for GitHub links tagged as "Exploit" or "Proof of Concept"
        github_pattern = r'href="(https://github\.com/[^\"]+)"[^>]*>(?:Exploit|Proof of Concept|PoC)'
        github_links = re.findall(github_pattern, html, re.IGNORECASE)
        
        results = []
        for link in github_links[:3]:  # Max 3 POCs per CVE
            if _is_authentic_poc_repo(link):
                results.append({"type": "github", "url": link, "cve": cve_id})
                print(f"  ✅ Found POC: {link}")
        
        return results
    except Exception as e:
        print(f"[PACKETSTORM] Error: {str(e)[:50]}")
        return []

def _search_github_api(service_name, version_info):
    """
    Use GitHub API to search for exploit repositories.
    """
    if not GITHUB_API_TOKEN:
        return []
    
    query = f"{service_name} {version_info} exploit POC vulnerability"
    print(f"[GITHUB_API] Searching: {query[:60]}...")
    
    headers = {
        'Authorization': f'token {GITHUB_API_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    try:
        search_url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc&per_page=5"
        response = requests.get(search_url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            print(f"[GITHUB_API] Failed: {response.status_code}")
            return []
        
        repos = response.json().get('items', [])
        authenticated_pocs = []
        
        for repo in repos[:3]:  # Top 3 results only
            repo_url = repo.get('html_url')
            stars = repo.get('stargazers_count', 0)
            
            # Filter junk
            if not _is_authentic_poc_repo(repo_url):
                continue
            
            if stars < 5:  # Skip low-quality repos
                continue
            
            authenticated_pocs.append({
                "url": repo_url,
                "stars": stars,
                "description": repo.get('description', 'N/A')[:100]
            })
            print(f"  ✅ Found: {repo.get('name')} ({stars}⭐)")
            
            time.sleep(0.3)  # Rate limiting
        
        return authenticated_pocs
    except Exception as e:
        print(f"[GITHUB_API] Error: {str(e)[:50]}")
        return []

def _is_authentic_poc_repo(url):
    """
    Filter out junk repositories.
    """
    url_lower = url.lower()
    
    junk_keywords = [
        'awesome', 'list', 'collection', 'guide', 'tutorial', 
        'pocs', 'vulnerability-list', 'cve-list', 'resources',
        'payloads', 'wordlist', 'cheatsheet'
    ]
    
    for keyword in junk_keywords:
        if keyword in url_lower:
            return False
    
    # Check path depth
    path_parts = urlparse(url).path.strip('/').split('/')
    if len(path_parts) > 3:
        return False
    
    return True

def _ai_validate_poc_relevance(readme_content, service_name, version):
    """
    Use AI to validate if POC is relevant and high-severity.
    """
    prompt = f"""
You are a security researcher. Analyze if this exploit is relevant and dangerous.

TARGET: {service_name} {version}
README (first 800 chars):
{readme_content[:800]}

CRITICAL CHECKS:
1. Is this for {service_name}?
2. Does it work on version {version} or similar?
3. Is it UNAUTHENTICATED?
4. Is severity HIGH/MEDIUM/CRITICAL (not LOW)?
5. Does it have actual code (not just theory)?

RESPOND JSON ONLY:
{{
    "is_relevant": true/false,
    "requires_auth": true/false,
    "severity": "HIGH/MEDIUM/CRITICAL/LOW",
    "reasoning": "brief"
}}
"""
    
    result = ask_ollama(prompt)
    if result:
        is_valid = (
            result.get('is_relevant', False) and
            not result.get('requires_auth', False) and
            result.get('severity') in ['HIGH', 'MEDIUM', 'CRITICAL']
        )
        return is_valid
    return False

def _extract_cves_from_nmap(nmap_output):
    """
    Extract CVE IDs from Nmap vulners script output.
    """
    cve_pattern = r'(CVE-\d{4}-\d{4,7})'
    cves = re.findall(cve_pattern, nmap_output)
    return list(set(cves))


def _process_single_cve(cve_id, service):
    """
    Process a single CVE (for parallel execution)
    """
    results = _fetch_cve_from_packetstorm(cve_id)
    pocs = []
    
    for result in results:
        if result['type'] == 'github':
            repo_context = clone_and_analyze_repo(result['url'])
            if repo_context:
                pocs.append({
                    "cve": cve_id,
                    "source": "PacketStorm",
                    "repo_url": result['url'],
                    "repo_context": repo_context[:3000]
                })
    
    return pocs

def execute_service_recon_and_vuln_scan(target, simulator_mode=False):
    if target.startswith(('http://', 'https://')):
        host = urlparse(target).hostname
    else:
        host = target
    
    print(f"\n{'='*80}")
    print(f"🔍 SMART VULNERABILITY RECONNAISSANCE")
    print(f"Target: {host}")
    print(f"{'='*80}\n")
    
    # Step 1: Fast port discovery with Naabu
    print(f"[NAABU] Fast port discovery...")
    naabu_ports = _run_naabu(host, top_ports=1000, rate=1000)
    
    if naabu_ports:
        ports_to_scan = ','.join(naabu_ports[:100])
        print(f"[NAABU] ✅ Found {len(naabu_ports)} open ports (scanning top 100)")
    else:
        ports_to_scan = NMAP_PORTS
        print(f"[NAABU] ⚠️  Fallback to default ports")
    
    # Step 2: Targeted Nmap scan on discovered ports
    nmap_command = ['nmap', '-sT', '-sV', '--open', '--script', 'vulners', '-p', ports_to_scan, host]
    print(f"[NMAP] Scanning {ports_to_scan.count(',') + 1} ports with service detection...")
    nmap_output = AICore.run_command(nmap_command)
    
    if not nmap_output:
        print("[NMAP] ❌ Scan failed")
        return {"services": []}
    
    services = _parse_nmap_output(nmap_output)
    print(f"[NMAP] ✅ Found {len(services)} services\n")
    
    # Step 3: Extract and FILTER CVEs
    all_cves = _extract_cves_from_nmap(nmap_output)
    critical_cves = _filter_critical_cves(all_cves, max_cves=5)
    
    if len(all_cves) > len(critical_cves):
        print(f"[CVE_FILTER] Filtered {len(all_cves)} CVEs → {len(critical_cves)} critical ones")
    
    # Step 4: Cleanup old clones
    clone_dir = os.path.join("Recon", "git_clones")
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
    os.makedirs(clone_dir, exist_ok=True)
    
    # Step 5: Find POCs for each service
    for service in services:
        port = service.get('port', '80').split('/')[0]
        service_name = service.get("service", "").lower()
        version_info = service.get('version_info', 'N/A')
        
        # Only process HTTP services with known versions
        is_http = "http" in service_name or port in ['80', '443', '8000', '8080', '8443']
        if not is_http or version_info == 'N/A':
            continue
        
        # HTTP fingerprinting with redirect following
        scheme = 'https' if port in ['443', '8443'] else 'http'
        url = f"{scheme}://{host}:{port}"
        try:
            final_url, redirect_chain = _get_final_url(url, timeout=5)
            if len(redirect_chain) > 1:
                service['redirect_info'] = {
                    'final_url': final_url,
                    'redirect_count': len(redirect_chain) - 1
                }
        except Exception:
            pass
        
        print(f"\n{'─'*60}")
        print(f"🎯 {service_name} {version_info} on port {port}")
        print(f"{'─'*60}")
        
        service["pocs_found"] = []
        
        # Step 5a: PARALLEL PacketStorm lookup (MUCH FASTER)
        if critical_cves:
            print(f"[PACKETSTORM] Checking {len(critical_cves)} critical CVEs in parallel...")
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_cve = {executor.submit(_process_single_cve, cve, service): cve for cve in critical_cves}
                
                for future in as_completed(future_to_cve):
                    pocs = future.result()
                    service["pocs_found"].extend(pocs)
        
        # Step 5b: GitHub API Search
        if GITHUB_API_TOKEN:
            github_results = _search_github_api(service_name, version_info)
            
            for result in github_results[:2]:
                repo_context = clone_and_analyze_repo(result['url'])
                if repo_context:
                    # Validate with AI
                    if _ai_validate_poc_relevance(repo_context[:1000], service_name, version_info):
                        service["pocs_found"].append({
                            "cve": "N/A",
                            "source": "GitHub API",
                            "repo_url": result['url'],
                            "repo_context": repo_context[:3000],
                            "stars": result['stars']
                        })
        
        print(f"\n✅ Found {len(service['pocs_found'])} relevant POCs for this service")
    
    # Step 6: Cleanup
    if os.path.exists(clone_dir):
        print(f"\n[CLEANUP] Removing cloned repos...")
        shutil.rmtree(clone_dir)
    
    print(f"\n{'='*80}")
    print(f"✅ RECONNAISSANCE COMPLETE")
    print(f"{'='*80}\n")
    
    return {"services": services}

def _parse_nmap_output(nmap_output):
    """Parse Nmap output to extract service information."""
    services = []
    current_service = None
    
    for line in nmap_output.splitlines():
        port_match = re.match(r'^\d+/\w+\s+open\s+(\S+)', line)
        if port_match:
            if current_service:
                services.append(current_service)
            
            current_service = {
                "port": port_match.group(1),
                "service": port_match.group(2)
            }
            
            # Clean version string
            raw_version_string = line[port_match.end():].strip()
            clean_version = re.sub(r'\s*\(\(.*\)\)\s*|\s*\(.*\)\s*', '', raw_version_string).strip()
            current_service['version_info'] = clean_version if clean_version else "N/A"
    
    if current_service:
        services.append(current_service)
    
    return services