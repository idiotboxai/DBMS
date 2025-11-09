import os
import subprocess
import shutil
def clone_and_analyze_repo(repo_url):
    try:
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        clone_dir = os.path.join("Recon", "git_clones", repo_name)
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir)
        os.makedirs(clone_dir, exist_ok=True)
        result = subprocess.run(['git', 'clone', '--depth', '1', repo_url, clone_dir], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return None
        context = []
        for root, dirs, files in os.walk(clone_dir):
            for file in files[:10]:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(2000)
                        context.append(f"File: {file}\n{content}\n")
                except:
                    continue
        return "\n".join(context)
    except Exception as e:
        print(f"Git clone error: {e}")
        return None
