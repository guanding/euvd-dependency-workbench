from __future__ import annotations

import os
from pathlib import Path

import uvicorn


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "outputs"
PID_PATH = DATA_DIR / "server.pid"

DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATA_DIR", str(DATA_DIR))
os.environ.setdefault("OUTPUT_DIR", str(OUTPUT_DIR))

PID_PATH.write_text(str(os.getpid()), encoding="ascii")
try:
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=int(os.getenv("MATCHER_PORT", "8090")),
        app_dir=str(ROOT),
        log_level="info",
    )
finally:
    try:
        if PID_PATH.read_text(encoding="ascii").strip() == str(os.getpid()):
            PID_PATH.unlink(missing_ok=True)
    except OSError:
        pass
