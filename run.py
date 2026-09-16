#!/usr/bin/env python3
"""
AmonStrike — CAI-Level Autonomous Pentesting
Autonomy Level 3-4. Based on published research.

Usage: sudo python3 run.py <url> [program]
"""
import sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

if len(sys.argv) < 2:
    print("Usage: sudo python3 run.py https://target.com [program]")
    sys.exit(1)

url     = sys.argv[1]
program = sys.argv[2] if len(sys.argv) > 2 else ""

from core.cai_engine import CAIOrchestrator
CAIOrchestrator(url, program).run()
