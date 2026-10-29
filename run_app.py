"""VeriBlue AI Launcher Script.
Run this script to launch the desktop application:
    python run_app.py
"""
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from veriblue_ai.main import main

if __name__ == "__main__":
    main()
