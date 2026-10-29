"""SAGE AI — Server Launch Runner.

Quickly start the backend API:
    python server.py
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
import uvicorn

# Ensure project root is importable
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Load local configuration without overriding variables supplied by the process.
load_dotenv(Path(PROJECT_ROOT) / ".env", override=False)

if __name__ == "__main__":
    host = os.getenv("API_HOST", "127.0.0.1")
    port = int(os.getenv("API_PORT", "8000"))

    print("=" * 60)
    print("  SAGE AI — Security Analysis & Guard Engine")
    print("=" * 60)
    print(f"  Backend API : http://{host}:{port}")
    print(f"  Swagger Docs: http://{host}:{port}/docs")
    print(f"  Health Check: http://{host}:{port}/health")
    print("=" * 60)

    uvicorn.run("backend.app:app", host=host, port=port, reload=True)
