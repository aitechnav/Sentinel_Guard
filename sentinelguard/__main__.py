"""Run the SentinelGuard CLI with ``python -m sentinelguard``."""

from __future__ import annotations

import sys

from sentinelguard.cli import main


if __name__ == "__main__":
    sys.exit(main())
