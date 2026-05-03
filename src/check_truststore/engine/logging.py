"""
TrustStore Analyzer & Visualizer - LOGGING & UI
Architect: Serge van Thillo
SPDX-License-Identifier: LGPL-3.0-or-later

This module provides high-level terminal logging with i18n support,
ANSI color-coded output, and Unicode iconography for consistent
status reporting across the engine.
"""

import sys
import gettext
from pathlib import Path
from typing import Optional

LOCALE_DIR = Path(__file__).parent.parent / "locale"
t = gettext.translation("check_truststore", localedir=str(LOCALE_DIR), fallback=True)
_ = t.gettext


class Status:
    """
    Represents a specific log level or status category.
    Handles the formatting of consistent, column-aligned terminal output.
    """

    def __init__(self, name: str, icon: str, color: str, translate: bool = True):
        """
        Initialize a logging status.

        Args:
            name: Internal ID or display name.
            icon: Unicode character/emoji representing the status.
            color: ANSI escape sequence for the status color.
            translate: Whether the name should be passed through gettext.
        """
        self.NAME: str = _(name) if translate else name
        self.ICON: str = icon
        self.COLOR: str = color
        self.USE_COLOR: bool = sys.stderr.isatty()

    def log(
        self,
        message: str,
        detail: str = "",
        label: Optional[str] = None,
        extra_icon: str = "  ",
    ) -> None:
        """
        Writes a formatted log line to sys.stderr.

        The output is structured into fixed-width columns:
        [ICON STATUS | EXTRA_ICONS | MESSAGE | DETAIL]

        Args:
            message: The primary description of the event.
            detail: Supplementary data (e.g., expiry dates or file paths).
            label: Optional override for the Status name.
            extra_icon: Additional icons (e.g., collision or signature status).
        """
        display_label = _(label) if label else self.NAME
        reset = "\033[0m" if self.USE_COLOR else ""
        color = self.COLOR if self.USE_COLOR else ""
        v_line = "\u2502"
        sep = f"{reset}{v_line}"

        # Calculate visual width for complex Unicode characters (Emojis)
        # to ensure column alignment remains intact.
        visual_width = 0
        for char in extra_icon:
            cp = ord(char)
            if 0xFE00 <= cp <= 0xFE0F:
                continue
            visual_width += 2 if cp > 127 else 1

        if not extra_icon.strip():
            formatted_icon = "          "
        else:
            extra_padding = 1 if "\U0001f6e1" in extra_icon else 0
            padding = " " * (max(0, 10 - visual_width) + extra_padding)
            formatted_icon = f"{extra_icon}{padding}"

        line = (
            f"{color}{self.ICON} {display_label:<14} {sep} "
            f"{formatted_icon} {sep} "
            f"{color}{message[:60]:<60} {sep} "
            f"{color}{detail}{reset}\n"
        )

        sys.stderr.write(line)
        sys.stderr.flush()

# ANSI Color Constants
C = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "MAGENTA": "\033[95m",
    "BLUE": "\033[94m",
    "RESET": "\033[0m"
}

# Predefined Status Instances
ERROR = Status("ERROR", "\U0000274c", C["RED"])  # ❌
OK = Status("OK", "\U00002705", C["GREEN"])  # ✅
WARNING = Status("WARNING", "\U000023f3", C["YELLOW"])  # ⏳
MISSING = Status("MISSING", "\U00002753", C["MAGENTA"], translate=False)  # ❓
COLLISION = Status("COLLISION", "\U0001f46f", C["CYAN"], translate=False)  # 👯
INFO = Status("INFO", "\U0001f535", C["BLUE"])  # 🔵
SYSTEM = Status("SYSTEM", "\U0001f4bb", C["BLUE"], translate=False)  # 💻
AIA = Status("AIA", "\U0001f310", C["CYAN"], translate=False)  # 🌐
REVOKED = Status("REVOKED", "\U0001f6ab", C["RED"])  # 🚫

class Icons:
    """
    Static repository of Unicode icons used for inline certificate status signaling
    within the TrustChainBuilder and Renderers.
    """

    VALID = "\U00002705"  # ✅ (White Heavy Check Mark)
    EXPIRED = "\U0000274c"  # ❌ (Cross Mark)
    WARNING = "\U00002757"  # ❗ (Warning Sign)
    LOCKED = "\U0001f512"  # 🔒 (Locked)
    BROKEN = "\U0001f4a5"  # 💥 (Broken Chain)
    UNKNOWN = "\U00002753"  # ❓ (Black Question Mark Ornament)
    AIA = "\U0001f310"  # 🌐 (Globe with Meridians)
    SYSTEM = "\U0001f4bb"  # 💻 (Laptop)
    OCSP_OK = "\U0001f6e1\ufe0f"  # 🛡️
    SIGNED = "\U00002611\ufe0f"  # ☑️
    UNCERTAIN = "\U00002754"  # ❔
    REVOKED = "\U0001f6ab"  # 🚫