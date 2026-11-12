# conftest.py – make pytest find the backend package when run from repo root.
# This file is intentionally minimal; all fixtures live in test files.
import sys
from pathlib import Path

# Insert the repo root so "from backend.xxx import yyy" resolves correctly
# whether pytest is invoked from the root or from backend/tests/.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

