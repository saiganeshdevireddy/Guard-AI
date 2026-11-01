"""
Startup script for Guard AI FastAPI backend.
"""
import sys
from pathlib import Path
import uvicorn

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

if __name__ == "__main__":
    print("==================================================")
    print("   GUARD AI - MULTI-AGENT CYBER DEFENCE BACKEND   ")
    print("   Running on: http://127.0.0.1:8000             ")
    print("   API Docs:   http://127.0.0.1:8000/docs        ")
    print("==================================================")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
