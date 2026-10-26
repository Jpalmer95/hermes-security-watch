#!/usr/bin/env python3
"""No-arg cron entry. Hermes cron runs a script path, not a command line.

Empty stdout is a silent success. Exit 0 when the watch itself ran.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["watch"]))
