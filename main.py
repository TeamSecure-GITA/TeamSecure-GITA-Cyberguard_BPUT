#!/usr/bin/env python3
"""CyberGuard AI Backend Runner

Enables running the backend from the project root using:
    python3 main.py

Automatically detects the virtual environment if packages are not found in the
global environment.
"""

import os
import sys

# Auto-detect and switch to virtual environment if dependencies are not in current environment
try:
    import fastapi  # noqa: F401
    import uvicorn
except ImportError:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "cyberguard-backend", ".venv", "bin", "python3"),
        os.path.join(base_dir, "cyberguard-backend", ".venv", "Scripts", "python.exe"),
        os.path.join(base_dir, "cyberguard-backend", "venv", "bin", "python3"),
        os.path.join(base_dir, "cyberguard-backend", "venv", "Scripts", "python.exe"),
        os.path.join(base_dir, ".venv", "bin", "python3"),
        os.path.join(base_dir, ".venv", "Scripts", "python.exe"),
    ]
    venv_python = next((p for p in candidates if os.path.exists(p)), None)
    if venv_python and sys.executable != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)
    else:
        print("[!] FastAPI/Uvicorn not found in current environment and no venv found.")
        print("[!] Please run: cd cyberguard-backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt")
        sys.exit(1)

# Ensure backend directory is in path and working directory is cyberguard-backend
backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberguard-backend")
if os.path.exists(backend_dir):
    os.chdir(backend_dir)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

if __name__ == "__main__":
    import uvicorn
    print("[*] Starting CyberGuard AI Backend on http://127.0.0.1:8000 ...")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
