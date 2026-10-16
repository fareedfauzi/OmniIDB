import sys
from pathlib import Path

# Add project root to sys.path so omni_idb is importable when executed directly or frozen
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

try:
    from omni_idb.app import run
except ImportError:
    from .app import run

if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else None)
