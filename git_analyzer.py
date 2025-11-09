# git_analyzer.py
"""
Git repository cloning and analysis utilities.
"""

import os
import shutil
import subprocess
from typing import Optional
from config import RECON_DIR


def clone_and_analyze_repo(repo_url: str, max_file_size: int = 500000) -> Optional[str]:
    """
    Clone a GitHub repository and analyze it for POC code.
    
    Args:
        repo_url: GitHub repository URL
        max_file_size: Maximum file size to analyze in bytes
        
    Returns:
        Repository context (README + code snippets) or None if failed
    """
    try:
        # Extract repo name from URL
        repo_name = repo_url.rstrip('/').split('/')[-1]
        clone_dir = os.path.join(RECON_DIR, "git_clones", repo_name)
        
        # Remove if already exists
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir)
            
        # Create parent directory
        os.makedirs(os.path.dirname(clone_dir), exist_ok=True)
        
        # Clone repository (shallow clone for speed)
        print(f"[GIT] Cloning {repo_name}...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, clone_dir],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            print(f"[GIT] Clone failed: {result.stderr[:100]}")
            return None
            
        # Analyze repository
        context = _analyze_repository(clone_dir, max_file_size)
        
        return context
        
    except subprocess.TimeoutExpired:
        print(f"[GIT] Clone timed out for {repo_url}")
        return None
    except Exception as e:
        print(f"[GIT] Error: {str(e)}")
        return None


def _analyze_repository(repo_path: str, max_file_size: int) -> str:
    """
    Analyze repository contents and extract relevant information.
    
    Args:
        repo_path: Path to cloned repository
        max_file_size: Maximum file size to analyze
        
    Returns:
        Repository context string
    """
    context_parts = []
    
    # Priority files to check
    priority_files = [
        "README.md", "README.txt", "README", "README.rst",
        "EXPLOIT.md", "POC.md", "VULNERABILITY.md",
        "exploit.py", "poc.py", "exploit.sh", "poc.sh"
    ]
    
    # Check priority files first
    for filename in priority_files:
        filepath = os.path.join(repo_path, filename)
        if os.path.isfile(filepath):
            try:
                size = os.path.getsize(filepath)
                if size <= max_file_size:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        context_parts.append(f"=== {filename} ===\n{content[:5000]}\n")
            except Exception as e:
                print(f"[GIT] Error reading {filename}: {str(e)}")
                
    # If we don't have enough content, scan for code files
    if len(''.join(context_parts)) < 2000:
        code_extensions = ['.py', '.sh', '.rb', '.pl', '.php', '.js', '.go', '.c', '.cpp']
        
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden directories and common non-relevant dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'vendor', 'test', 'tests']]
            
            for filename in files:
                if any(filename.endswith(ext) for ext in code_extensions):
                    filepath = os.path.join(root, filename)
                    try:
                        size = os.path.getsize(filepath)
                        if size <= max_file_size:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                relative_path = os.path.relpath(filepath, repo_path)
                                context_parts.append(f"=== {relative_path} ===\n{content[:3000]}\n")
                                
                            # Limit total context
                            if len(''.join(context_parts)) > 10000:
                                break
                    except Exception:
                        continue
                        
            if len(''.join(context_parts)) > 10000:
                break
                
    return ''.join(context_parts)


def cleanup_git_clones():
    """Remove all cloned repositories."""
    clone_dir = os.path.join(RECON_DIR, "git_clones")
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
        print(f"[GIT] Cleaned up {clone_dir}")
