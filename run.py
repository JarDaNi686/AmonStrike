#!/usr/bin/env python3
"""
AmonStrike — Professional Pentest Engine
Real methodology. No noise. Evidence-based findings only.

Usage: sudo python3 run.py https://target.com [program_handle]
"""
import sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

if len(sys.argv) < 2:
    print("Usage: sudo python3 run.py https://target.com [program]")
    sys.exit(1)

url     = sys.argv[1]
program = sys.argv[2] if len(sys.argv) > 2 else ""

from core.pro_engine import ProPentest
ProPentest(url, program).run()
