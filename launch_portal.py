#!/usr/bin/env python3
"""Quick launcher for AndroidINONE Portal."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portal.run import main

if __name__ == "__main__":
    main()
