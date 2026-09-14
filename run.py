#!/usr/bin/env python3
"""
AmonStrike — One URL in. Everything out.
Usage: sudo python3 run.py <H1_program_URL>
"""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

if len(sys.argv) < 2:
    print("Usage: sudo python3 run.py https://target.com [program_handle]")
    print("Example: sudo python3 run.py https://www.army.mil dod")
    sys.exit(1)

url    = sys.argv[1]
handle = sys.argv[2] if len(sys.argv) > 2 else ""

from core.master_engine import MasterEngine
engine = MasterEngine(url, handle)
engine.run()
