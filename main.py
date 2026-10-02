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
base_dir = os.path.dirname(os.path.abspath(__file__))
candidates = [
    os.path.join(base_dir, "cyberguard-backend", ".venv", "bin", "python3"),
    os.path.join(base_dir, "cyberguard-backend", ".venv", "Scripts", "python.exe"),
    os.path.join(base_dir, "cyberguard-backend", "venv", "bin", "python3"),
    os.path.join(base_dir, "cyberguard-backend", "venv", "Scripts", "python.exe"),
    os.path.join(base_dir, ".venv", "bin", "python3"),
    os.path.join(base_dir, ".venv", "Scripts", "python.exe"),
]
venv_python = next((p for p in candidates if os.path.isfile(p) and os.access(p, os.X_OK)), None)

need_switch = False
try:
    import fastapi  # noqa: F401
    import uvicorn  # noqa: F401
    import webauthn  # noqa: F401
    import jwt  # noqa: F401
except ImportError:
    need_switch = True

if venv_python and sys.executable != venv_python and (need_switch or "cyberguard-backend" in venv_python):
    try:
        os.execv(venv_python, [venv_python] + sys.argv)
    except OSError:
        pass

if need_switch:
    print("[!] Required backend packages (fastapi, uvicorn, webauthn, pyjwt) not found in current environment.", flush=True)
    print("[!] Please run: cd cyberguard-backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt", flush=True)
    sys.exit(1)

# Ensure backend directory is in path and working directory is cyberguard-backend
backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberguard-backend")
if os.path.exists(backend_dir):
    os.chdir(backend_dir)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload_env = os.getenv("RELOAD")
    is_prod = bool(os.getenv("RENDER") or os.getenv("CYBERGUARD_ENV") == "production" or "PORT" in os.environ)
    reload = reload_env.lower() in ("true", "1") if reload_env is not None else not is_prod
    print(f"[*] Starting CyberGuard AI Backend on http://{host}:{port} (reload={reload}) ...", flush=True)
    uvicorn.run("main:app", host=host, port=port, reload=reload, proxy_headers=True, forwarded_allow_ips="*")

