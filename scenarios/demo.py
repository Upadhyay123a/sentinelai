"""One-command demo for recording a GIF: flagship OFF/ON, then the red-team run.

Short pauses between sections so the recording reads cleanly.

    python -m scenarios.demo
"""
from __future__ import annotations

import time

from gateway.config import EnforcementMode
from redteam import runner as redteam_runner
from scenarios.flagship_exfil import run as run_flagship


def _banner(text: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def main() -> None:
    _banner("SentinelAI - lethal-trifecta containment for AI agents")
    time.sleep(1.5)

    _banner("1) Attack WITHOUT SentinelAI  (gateway DISABLED)")
    time.sleep(0.8)
    run_flagship(EnforcementMode.DISABLED)
    time.sleep(2.0)

    _banner("2) Same attack WITH SentinelAI  (gateway ENFORCE)")
    time.sleep(0.8)
    run_flagship(EnforcementMode.ENFORCE)
    time.sleep(2.0)

    _banner("3) Red-team harness - 4 attack variants scored")
    time.sleep(0.8)
    redteam_runner.main()
    time.sleep(1.5)

    _banner("Leaked when OFF, blocked when ON. 0 false negatives.")


if __name__ == "__main__":
    main()
