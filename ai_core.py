import subprocess
import json
class AICore:
    @staticmethod
    def run_command(command, timeout=30):
        try:
            if isinstance(command, list):
                result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout if result.returncode == 0 else None
        except Exception as e:
            print(f"Command execution error: {e}")
            return None
def perform_web_search(query):
    return []
def ask_ollama(prompt):
    return None
