"""Colored narration of what each party does."""

import os
import sys
import time

_COLORS = {
    "ALICE": "\033[34m",    # blue
    "BOB": "\033[32m",      # green
    "MALLORY": "\033[31m",  # red
    "CHANNEL": "\033[90m",  # grey
}
_BOLD = "\033[1m"
_RESET = "\033[0m"

_use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
_delay = 0.0
_quiet = False
_sink = None


def configure(delay: float = 0.0, color: bool | None = None, quiet: bool = False):
    global _delay, _use_color, _quiet
    _delay = delay
    _quiet = quiet
    if color is not None:
        _use_color = color


def set_sink(sink):
    """Send narration to `sink(party, text)` instead of stdout.

    Headings arrive with party None. Pass None to go back to printing.
    """
    global _sink
    _sink = sink


def say(party: str, text: str):
    if _quiet:
        return
    if _sink is not None:
        _sink(party, text)
    else:
        label = f"[{party}]".ljust(10)
        if _use_color:
            label = f"{_COLORS.get(party, '')}{_BOLD}{label}{_RESET}"
        print(f"{label} {text}", flush=True)
    if _delay:
        time.sleep(_delay)


def heading(text: str):
    if _quiet:
        return
    if _sink is not None:
        _sink(None, text)
        return
    line = f"== {text} =="
    print(f"\n{_BOLD}{line}{_RESET}" if _use_color else f"\n{line}", flush=True)


def short_hex(data: bytes, limit: int = 24) -> str:
    """Truncated hex, so ciphertexts don't flood the screen."""
    h = data.hex()
    return h if len(h) <= limit * 2 else f"{h[: limit * 2]}... ({len(data)} bytes)"
