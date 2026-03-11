#!/usr/bin/env python3
"""AndroidINONE Portal – Entry point."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from portal.config import PORTAL_HOST, PORTAL_PORT


BANNER = r"""
\033[38;5;39m
    ╔═══════════════════════════════════════════════════════════╗
    ║  🛡️  AndroidINONE Portal – Security Command Center  🛡️    ║
    ║     Static • Dynamic • Frida • Drozer • OWASP • Reports  ║
    ╚═══════════════════════════════════════════════════════════╝
\033[0m\033[38;5;242m
              Android Security Assessment Platform
                        Version 2.0.0
\033[0m"""


def main():
    print(BANNER)
    print(f"\033[1;32m  ▶ Starting portal at http://localhost:{PORTAL_PORT}\033[0m")
    print(f"\033[38;5;242m  ▶ API docs at http://localhost:{PORTAL_PORT}/docs\033[0m")
    print(f"\033[38;5;242m  ▶ Press Ctrl+C to stop\033[0m\n")

    uvicorn.run(
        "portal.app:app",
        host=PORTAL_HOST,
        port=PORTAL_PORT,
        reload=False,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
