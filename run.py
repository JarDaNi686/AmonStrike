#!/usr/bin/env python3
"""
AmonStrike — One URL in. Everything out.
Usage: sudo python3 run.py https://target.com [program]
"""
import sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

if len(sys.argv) < 2:
    print("Usage: sudo python3 run.py https://target.com [program_handle]")
    print("Example: sudo python3 run.py https://claude.ai anthropic")
    sys.exit(1)

url     = sys.argv[1]
program = sys.argv[2] if len(sys.argv) > 2 else ""
no_burp = "--no-burp" in sys.argv

from core.orchestrator import MasterOrchestrator
orch = MasterOrchestrator(url, program, use_burp=not no_burp)
orch.run()
