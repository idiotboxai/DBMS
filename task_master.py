# task_master.py
"""
AI-powered task orchestration and decision making.
"""

from typing import Dict, List, Optional, Any
from ai_core import ask_ollama


def analyze_scan_results(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use AI to analyze scan results and provide recommendations.
    
    Args:
        scan_results: Dictionary containing scan results
        
    Returns:
        Analysis results with recommendations
    """
    print("\n[AI_ANALYSIS] Analyzing scan results...")
    
    # Prepare summary for AI
    summary = f"""
Scan Results Summary:
- Services Found: {len(scan_results.get('services', []))}
- Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}
- Open Ports: {len(scan_results.get('ports', []))}

Services:
{_format_services(scan_results.get('services', []))}

Vulnerabilities:
{_format_vulnerabilities(scan_results.get('vulnerabilities', []))}
"""

    prompt = f"""You are a security analyst. Analyze these scan results and provide recommendations.

{summary}

Provide analysis in JSON format:
{{
    "risk_level": "LOW/MEDIUM/HIGH/CRITICAL",
    "priority_targets": ["list of services/vulnerabilities to focus on"],
    "recommended_actions": ["list of recommended next steps"],
    "concerns": ["list of security concerns"],
    "quick_wins": ["list of easy-to-exploit vulnerabilities"]
}}
"""

    result = ask_ollama(prompt, json_mode=True)
    
    if result:
        print(f"[AI_ANALYSIS] ✅ Risk Level: {result.get('risk_level', 'UNKNOWN')}")
        return result
    else:
        print("[AI_ANALYSIS] ❌ Analysis failed")
        return {
            'risk_level': 'UNKNOWN',
            'priority_targets': [],
            'recommended_actions': [],
            'concerns': [],
            'quick_wins': []
        }


def prioritize_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Use AI to prioritize vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Prioritized list of vulnerabilities
    """
    print("\n[AI_PRIORITIZE] Prioritizing vulnerabilities...")
    
    if not vulnerabilities:
        return []
    
    # Create summary
    vuln_summary = "\n".join([
        f"{i+1}. {v.get('cve_id', 'N/A')} - {v.get('description', 'No description')[:100]} (CVSS: {v.get('cvss_score', 0)})"
        for i, v in enumerate(vulnerabilities[:20])
    ])
    
    prompt = f"""You are a security expert. Prioritize these vulnerabilities for exploitation.

Vulnerabilities:
{vuln_summary}

Consider:
1. Exploitability (ease of exploitation)
2. Impact (severity of successful exploit)
3. Availability of POCs
4. Common in real-world attacks

Return JSON array with vulnerability indices in priority order:
{{
    "priority_order": [0, 2, 1, ...],
    "reasoning": "brief explanation"
}}
"""

    result = ask_ollama(prompt, json_mode=True)
    
    if result and 'priority_order' in result:
        priority_order = result['priority_order']
        prioritized = []
        
        for index in priority_order:
            if 0 <= index < len(vulnerabilities):
                prioritized.append(vulnerabilities[index])
                
        # Add any missing vulnerabilities at the end
        for vuln in vulnerabilities:
            if vuln not in prioritized:
                prioritized.append(vuln)
                
        print(f"[AI_PRIORITIZE] ✅ Prioritized {len(prioritized)} vulnerabilities")
        return prioritized
    else:
        print("[AI_PRIORITIZE] ⚠️ Using default CVSS-based priority")
        return sorted(vulnerabilities, key=lambda v: v.get('cvss_score', 0), reverse=True)


def suggest_next_steps(current_state: Dict[str, Any]) -> List[str]:
    """
    Use AI to suggest next steps in penetration testing.
    
    Args:
        current_state: Current state of testing
        
    Returns:
        List of suggested next steps
    """
    print("\n[AI_SUGGEST] Generating next steps...")
    
    prompt = f"""You are a penetration tester. Based on current progress, suggest next steps.

Current State:
- Phase: {current_state.get('phase', 'reconnaissance')}
- Completed Tasks: {', '.join(current_state.get('completed', []))}
- Findings: {len(current_state.get('findings', []))} vulnerabilities found
- Services: {', '.join(current_state.get('services', []))}

Suggest 3-5 specific next steps to continue the assessment.

Return JSON:
{{
    "next_steps": ["step 1", "step 2", ...],
    "reasoning": "brief explanation"
}}
"""

    result = ask_ollama(prompt, json_mode=True)
    
    if result and 'next_steps' in result:
        steps = result['next_steps']
        print(f"[AI_SUGGEST] ✅ Generated {len(steps)} suggestions")
        return steps
    else:
        print("[AI_SUGGEST] ⚠️ Using default suggestions")
        return [
            "Continue service enumeration",
            "Test discovered vulnerabilities",
            "Perform manual verification",
            "Document findings"
        ]


def generate_executive_summary(results: Dict[str, Any]) -> str:
    """
    Generate executive summary of findings.
    
    Args:
        results: Complete test results
        
    Returns:
        Executive summary text
    """
    print("\n[AI_SUMMARY] Generating executive summary...")
    
    prompt = f"""You are a security consultant. Create an executive summary of these penetration test results.

Results:
- Target: {results.get('target', 'Unknown')}
- Services Found: {len(results.get('services', []))}
- Vulnerabilities: {len(results.get('vulnerabilities', []))}
- Critical: {results.get('critical_count', 0)}
- High: {results.get('high_count', 0)}
- Medium: {results.get('medium_count', 0)}

Key Findings:
{_format_vulnerabilities(results.get('vulnerabilities', [])[:5])}

Create a professional executive summary (200-300 words) suitable for management.
Focus on business impact and recommendations.

Return plain text only (no JSON).
"""

    result = ask_ollama(prompt, json_mode=False)
    
    if result:
        summary = result.get('response', '')
        print(f"[AI_SUMMARY] ✅ Generated summary ({len(summary)} chars)")
        return summary
    else:
        print("[AI_SUMMARY] ❌ Generation failed")
        return "Executive summary generation failed."


def _format_services(services: List[Dict[str, Any]]) -> str:
    """Format services for display."""
    if not services:
        return "None found"
    
    lines = []
    for service in services[:10]:
        lines.append(f"- {service.get('service', 'Unknown')} on port {service.get('port', 'Unknown')}")
    
    if len(services) > 10:
        lines.append(f"... and {len(services) - 10} more")
        
    return "\n".join(lines)


def _format_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Format vulnerabilities for display."""
    if not vulnerabilities:
        return "None found"
    
    lines = []
    for vuln in vulnerabilities[:10]:
        cve = vuln.get('cve_id', 'N/A')
        severity = vuln.get('severity', 'unknown').upper()
        desc = vuln.get('description', 'No description')[:80]
        lines.append(f"- {cve} ({severity}): {desc}")
    
    if len(vulnerabilities) > 10:
        lines.append(f"... and {len(vulnerabilities) - 10} more")
        
    return "\n".join(lines)


class TaskMaster:
    """Orchestrates penetration testing tasks using AI."""
    
    def __init__(self):
        self.state = {
            'phase': 'reconnaissance',
            'completed': [],
            'findings': [],
            'services': []
        }
        
    def update_state(self, task: str, results: Any):
        """Update task state."""
        self.state['completed'].append(task)
        
        if isinstance(results, dict):
            if 'services' in results:
                self.state['services'].extend(results['services'])
            if 'vulnerabilities' in results:
                self.state['findings'].extend(results['vulnerabilities'])
                
    def get_next_tasks(self) -> List[str]:
        """Get recommended next tasks."""
        return suggest_next_steps(self.state)
        
    def analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze results using AI."""
        return analyze_scan_results(results)
