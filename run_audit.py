"""No-install launcher; requires only Python 3.11+ and this source tree."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from offline_auditor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
