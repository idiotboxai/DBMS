# nuclei_generator.py
"""
AI-powered Nuclei template generator with strict quality controls.
"""

import re
import yaml
import hashlib
from typing import Dict, List, Optional, Any
from ai_core import ask_ollama
from config import FAKE_AUTHORS, NUCLEI_TEMPLATE_DIR
from recon_cache import get_cache


class POCAnalyzer:
    """Analyzes POC code to extract structured information."""
    
    @staticmethod
    def prioritize_files(repo_context: str) -> List[Dict[str, str]]:
        """
        Extract and prioritize files from repository context.
        
        Args:
            repo_context: Repository content string
            
        Returns:
            List of files with priority scoring
        """
        files = []
        
        # Split by file markers
        file_sections = re.split(r'=== (.+?) ===', repo_context)
        
        for i in range(1, len(file_sections), 2):
            if i + 1 < len(file_sections):
                filename = file_sections[i]
                content = file_sections[i + 1]
                
                priority = POCAnalyzer._calculate_file_priority(filename, content)
                
                files.append({
                    'filename': filename,
                    'content': content,
                    'priority': priority
                })
                
        # Sort by priority
        files.sort(key=lambda x: x['priority'], reverse=True)
        
        return files
        
    @staticmethod
    def _calculate_file_priority(filename: str, content: str) -> int:
        """Calculate priority score for a file."""
        score = 0
        filename_lower = filename.lower()
        content_lower = content.lower()
        
        # High priority files
        if any(name in filename_lower for name in ['exploit', 'poc', 'vulnerability', 'payload']):
            score += 100
            
        # README files
        if 'readme' in filename_lower:
            score += 80
            
        # Code files with exploit-related content
        code_keywords = ['exploit', 'vulnerability', 'payload', 'shell', 'rce', 'sqli', 'xss']
        keyword_count = sum(1 for keyword in code_keywords if keyword in content_lower)
        score += keyword_count * 10
        
        # Request/response patterns
        if any(pattern in content_lower for pattern in ['http request', 'post ', 'get ', 'curl', 'requests.']):
            score += 20
            
        # CVE references
        cve_count = len(re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE))
        score += cve_count * 15
        
        return score
        
    @staticmethod
    def extract_structured_info(content: str) -> Dict[str, Any]:
        """
        Extract structured information from POC content.
        
        Args:
            content: POC file content
            
        Returns:
            Dict with URLs, paths, methods, parameters, payloads
        """
        info = {
            'urls': [],
            'paths': [],
            'methods': [],
            'parameters': [],
            'payloads': [],
            'headers': []
        }
        
        # Extract URLs
        url_pattern = r'https?://[^\s\'"<>]+'
        info['urls'] = list(set(re.findall(url_pattern, content)))[:10]
        
        # Extract paths
        path_pattern = r'["\']/([\w/\-_.]+)["\']'
        info['paths'] = list(set(re.findall(path_pattern, content)))[:10]
        
        # Extract HTTP methods
        method_pattern = r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b'
        info['methods'] = list(set(re.findall(method_pattern, content, re.IGNORECASE)))
        
        # Extract parameters
        param_patterns = [
            r'[\?&](\w+)=',  # URL parameters
            r'["\'](\w+)["\']:\s*["\']',  # JSON keys
            r'data\[[\'"](w+)[\'"]\]',  # Array keys
        ]
        
        for pattern in param_patterns:
            params = re.findall(pattern, content)
            info['parameters'].extend(params)
            
        info['parameters'] = list(set(info['parameters']))[:20]
        
        # Extract common payload patterns
        payload_patterns = [
            r'<script[^>]*>.*?</script>',  # XSS
            r'["\'].*?(?:union|select|insert|update|delete).*?["\']',  # SQLi
            r'{{.*?}}',  # SSTI
            r'\$\{.*?\}',  # Expression injection
            r'\.\./+',  # Path traversal
        ]
        
        for pattern in payload_patterns:
            payloads = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            info['payloads'].extend([p[:100] for p in payloads])
            
        info['payloads'] = list(set(info['payloads']))[:10]
        
        # Extract headers
        header_pattern = r'["\']?(X-[\w-]+|Authorization|Cookie|Content-Type)["\']?\s*:\s*["\']?([^"\'\n]+)'
        headers = re.findall(header_pattern, content, re.IGNORECASE)
        info['headers'] = [f"{h[0]}: {h[1][:50]}" for h in headers[:10]]
        
        return info
        
    @staticmethod
    def detect_vulnerability_type(content: str, cve_description: str = "") -> str:
        """
        Detect vulnerability type from POC content and CVE description.
        
        Args:
            content: POC content
            cve_description: CVE description text
            
        Returns:
            Vulnerability type string
        """
        combined = (content + " " + cve_description).lower()
        
        # Define patterns for different vulnerability types
        vuln_patterns = {
            'rce': ['remote code execution', 'rce', 'command injection', 'shell', 'exec(', 'system('],
            'sqli': ['sql injection', 'sqli', 'union select', 'mysql', 'postgresql', 'mssql'],
            'xss': ['cross-site scripting', 'xss', '<script', 'alert(', 'onerror='],
            'ssrf': ['server-side request forgery', 'ssrf', 'url=http', 'fetch(http'],
            'lfi': ['local file inclusion', 'lfi', 'file=../', 'path=../', '/etc/passwd'],
            'rfi': ['remote file inclusion', 'rfi', 'include(http', 'require(http'],
            'xxe': ['xml external entity', 'xxe', '<!entity', 'doctype'],
            'ssti': ['server-side template injection', 'ssti', '{{', '${'],
            'idor': ['insecure direct object reference', 'idor', 'user_id=', 'id='],
            'csrf': ['cross-site request forgery', 'csrf', 'token', 'authenticity'],
            'auth-bypass': ['authentication bypass', 'auth bypass', 'login bypass'],
            'directory-traversal': ['directory traversal', 'path traversal', '../'],
            'deserialization': ['deserialization', 'unserialize', 'pickle'],
        }
        
        scores = {}
        for vuln_type, patterns in vuln_patterns.items():
            score = sum(1 for pattern in patterns if pattern in combined)
            if score > 0:
                scores[vuln_type] = score
                
        if scores:
            return max(scores.items(), key=lambda x: x[1])[0]
        else:
            return 'other'


class TemplateValidator:
    """Validates Nuclei templates for quality and authenticity."""
    
    @staticmethod
    def is_fake_author(template_yaml: str) -> bool:
        """
        Check if template has fake/AI-generated author.
        
        Args:
            template_yaml: Template YAML content
            
        Returns:
            True if fake author detected
        """
        try:
            data = yaml.safe_load(template_yaml)
            
            if 'info' not in data:
                return True
                
            info = data['info']
            author = info.get('author', '').lower()
            
            # Check against fake author list
            for fake in FAKE_AUTHORS:
                if fake in author:
                    print(f"[VALIDATOR] ❌ Fake author detected: {author}")
                    return True
                    
            # Check for AI-generated patterns
            ai_patterns = [
                'generated by',
                'created by ai',
                'automated',
                'synthetic',
            ]
            
            description = info.get('description', '').lower()
            for pattern in ai_patterns:
                if pattern in description:
                    print(f"[VALIDATOR] ❌ AI-generated pattern detected")
                    return True
                    
            return False
            
        except Exception as e:
            print(f"[VALIDATOR] Error parsing template: {str(e)}")
            return True
            
    @staticmethod
    def validate_yaml_structure(template_yaml: str) -> bool:
        """
        Validate YAML structure of template.
        
        Args:
            template_yaml: Template YAML content
            
        Returns:
            True if valid
        """
        try:
            data = yaml.safe_load(template_yaml)
            
            # Check required fields
            required_fields = ['id', 'info', 'requests']
            for field in required_fields:
                if field not in data:
                    print(f"[VALIDATOR] ❌ Missing required field: {field}")
                    return False
                    
            # Validate info section
            info = data['info']
            required_info = ['name', 'author', 'severity', 'description']
            for field in required_info:
                if field not in info:
                    print(f"[VALIDATOR] ❌ Missing info field: {field}")
                    return False
                    
            # Validate severity
            valid_severities = ['info', 'low', 'medium', 'high', 'critical']
            if info['severity'].lower() not in valid_severities:
                print(f"[VALIDATOR] ❌ Invalid severity: {info['severity']}")
                return False
                
            # Validate requests section
            if not isinstance(data['requests'], list) or len(data['requests']) == 0:
                print(f"[VALIDATOR] ❌ Invalid requests section")
                return False
                
            return True
            
        except yaml.YAMLError as e:
            print(f"[VALIDATOR] ❌ YAML parse error: {str(e)}")
            return False
        except Exception as e:
            print(f"[VALIDATOR] ❌ Validation error: {str(e)}")
            return False
            
    @staticmethod
    def validate_cve_description_match(template_yaml: str, cve_description: str) -> bool:
        """
        Validate that template matches CVE description.
        
        Args:
            template_yaml: Template YAML content
            cve_description: CVE description
            
        Returns:
            True if matches
        """
        try:
            data = yaml.safe_load(template_yaml)
            info = data.get('info', {})
            
            template_desc = info.get('description', '').lower()
            cve_desc_lower = cve_description.lower()
            
            # Extract key terms from CVE description
            key_terms = re.findall(r'\b\w{4,}\b', cve_desc_lower)
            key_terms = [t for t in key_terms if t not in ['that', 'this', 'with', 'from', 'have']]
            
            # Check if template description contains key terms
            matches = sum(1 for term in key_terms[:10] if term in template_desc)
            
            match_ratio = matches / min(len(key_terms), 10) if key_terms else 0
            
            if match_ratio < 0.3:
                print(f"[VALIDATOR] ⚠️ Low CVE description match: {match_ratio:.2f}")
                return False
                
            return True
            
        except Exception as e:
            print(f"[VALIDATOR] Error in CVE matching: {str(e)}")
            return False


class NucleiGenerator:
    """Main Nuclei template generator class."""
    
    def __init__(self):
        self.cache = get_cache()
        self.analyzer = POCAnalyzer()
        self.validator = TemplateValidator()
        
    def generate_template(self, cve_id: str, cve_description: str, 
                         poc_context: str, service_info: Dict[str, str]) -> Optional[str]:
        """
        Generate a Nuclei template from CVE and POC information.
        
        Args:
            cve_id: CVE identifier
            cve_description: CVE description
            poc_context: POC code context
            service_info: Service information dict
            
        Returns:
            Nuclei template YAML string or None
        """
        print(f"\n[NUCLEI] Generating template for {cve_id}")
        
        # Check cache first
        template_id = f"CVE-{cve_id}"
        cached = self.cache.get_cached_template(template_id)
        if cached:
            print(f"[NUCLEI] ✅ Using cached template")
            return cached[0]
            
        # Analyze POC files
        files = self.analyzer.prioritize_files(poc_context)
        
        if not files:
            print(f"[NUCLEI] ❌ No files to analyze")
            return None
            
        # Extract structured information from top files
        structured_info = {}
        for file_info in files[:3]:  # Top 3 files
            info = self.analyzer.extract_structured_info(file_info['content'])
            
            # Merge information
            for key in info:
                if key not in structured_info:
                    structured_info[key] = []
                structured_info[key].extend(info[key])
                
        # Deduplicate
        for key in structured_info:
            structured_info[key] = list(set(structured_info[key]))
            
        # Detect vulnerability type
        vuln_type = self.analyzer.detect_vulnerability_type(poc_context, cve_description)
        
        # Generate template using AI
        template_yaml = self._generate_with_ai(
            cve_id, cve_description, vuln_type, 
            structured_info, service_info, files[0]['content']
        )
        
        if not template_yaml:
            print(f"[NUCLEI] ❌ AI generation failed")
            return None
            
        # Validate template
        if not self._validate_template(template_yaml, cve_description):
            print(f"[NUCLEI] ❌ Template validation failed")
            return None
            
        # Cache template
        metadata = {
            'cve_id': cve_id,
            'vuln_type': vuln_type,
            'service': service_info.get('service', 'unknown')
        }
        self.cache.cache_template(template_id, template_yaml, metadata)
        
        print(f"[NUCLEI] ✅ Template generated successfully")
        return template_yaml
        
    def _generate_with_ai(self, cve_id: str, cve_description: str,
                         vuln_type: str, structured_info: Dict,
                         service_info: Dict, top_file_content: str) -> Optional[str]:
        """Generate template using AI with enhanced prompts."""
        
        prompt = f"""You are a security researcher creating a Nuclei template for vulnerability scanning.

CVE: {cve_id}
VULNERABILITY TYPE: {vuln_type}
DESCRIPTION: {cve_description}

SERVICE INFO:
- Name: {service_info.get('service', 'unknown')}
- Version: {service_info.get('version_info', 'unknown')}
- Port: {service_info.get('port', 'unknown')}

EXTRACTED POC INFORMATION:
- URLs: {', '.join(structured_info.get('urls', [])[:5])}
- Paths: {', '.join(structured_info.get('paths', [])[:5])}
- HTTP Methods: {', '.join(structured_info.get('methods', []))}
- Parameters: {', '.join(structured_info.get('parameters', [])[:10])}
- Payloads: {', '.join([p[:50] for p in structured_info.get('payloads', [])][:3])}

TOP POC FILE (first 2000 chars):
{top_file_content[:2000]}

REQUIREMENTS:
1. Create a valid Nuclei YAML template
2. Use author: "projectdiscovery" (only official authors)
3. Set appropriate severity (critical/high/medium/low)
4. Include accurate matchers for vulnerability detection
5. Use the extracted paths, parameters, and payloads
6. Add clear description matching the CVE
7. Include CVE reference in classification section
8. Make it production-ready (no placeholders)

OUTPUT ONLY THE YAML TEMPLATE (no explanations):
"""

        result = ask_ollama(prompt, json_mode=False)
        
        if not result:
            return None
            
        response_text = result.get('response', '')
        
        # Extract YAML from markdown code blocks if present
        if '```yaml' in response_text:
            start = response_text.find('```yaml') + 7
            end = response_text.find('```', start)
            yaml_content = response_text[start:end].strip()
        elif '```' in response_text:
            start = response_text.find('```') + 3
            end = response_text.find('```', start)
            yaml_content = response_text[start:end].strip()
        else:
            yaml_content = response_text.strip()
            
        return yaml_content
        
    def _validate_template(self, template_yaml: str, cve_description: str) -> bool:
        """Validate generated template."""
        
        # Check for fake authors
        if self.validator.is_fake_author(template_yaml):
            return False
            
        # Validate YAML structure
        if not self.validator.validate_yaml_structure(template_yaml):
            return False
            
        # Validate CVE description match
        if not self.validator.validate_cve_description_match(template_yaml, cve_description):
            return False
            
        return True
        
    def select_best_template(self, templates: List[str], cve_description: str) -> Optional[str]:
        """
        Select best template from multiple options using AI.
        
        Args:
            templates: List of template YAML strings
            cve_description: CVE description for validation
            
        Returns:
            Best template or None
        """
        if not templates:
            return None
            
        if len(templates) == 1:
            return templates[0] if self._validate_template(templates[0], cve_description) else None
            
        # Filter out invalid templates
        valid_templates = [t for t in templates if self._validate_template(t, cve_description)]
        
        if not valid_templates:
            return None
            
        if len(valid_templates) == 1:
            return valid_templates[0]
            
        # Use AI to select best template
        prompt = f"""You are a security expert evaluating Nuclei templates.

CVE DESCRIPTION: {cve_description}

TEMPLATE OPTIONS:
{chr(10).join([f"--- TEMPLATE {i+1} ---{chr(10)}{t[:500]}{chr(10)}" for i, t in enumerate(valid_templates[:3])])}

Select the BEST template based on:
1. Accuracy of vulnerability detection
2. Quality of matchers
3. Completeness of information
4. Production-readiness

RESPOND JSON ONLY:
{{
    "selected_index": 0-2,
    "reasoning": "brief explanation"
}}
"""

        result = ask_ollama(prompt, json_mode=True)
        
        if result and 'selected_index' in result:
            index = result['selected_index']
            if 0 <= index < len(valid_templates):
                return valid_templates[index]
                
        # Fallback: return first valid template
        return valid_templates[0]
