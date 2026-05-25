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
from typing import Dict, Optional

LOCALE_DIR = Path(__file__).parent.parent / "locale"
t = gettext.translation("check_truststore", localedir=str(LOCALE_DIR), fallback=True)
_ = t.gettext


class Status:
    """
    Represents a specific log level or status category.
    Handles the formatting of consistent, column-aligned terminal output.
    """

    def __init__(self, name: str, icon: str, color: str, translate: bool = True) -> None:
        """Initializes a logging status instance.

        Args:
            name: Internal ID or default display name for the status.
            icon: Unicode character or emoji representing the status visually.
            color: ANSI escape sequence used for colorizing the terminal output.
            translate: Whether the status name should be translated via gettext.
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
        """Writes a structured, column-aligned log line to sys.stderr.

        The output is deterministically formatted into fixed-width columns:
        [ICON STATUS | EXTRA_ICONS | MESSAGE | DETAIL]

        Args:
            message: The primary description of the logged event.
            detail: Supplementary technical data (e.g., fingerprints, dates or paths).
            label: Optional string to override the default Status name.
            extra_icon: Additional contextual icons (e.g., signature or collision status).
        """
        display_label: str = _(label) if label else self.NAME
        reset: str = "\033[0m" if self.USE_COLOR else ""
        color: str = self.COLOR if self.USE_COLOR else ""
        v_line: str = "\u2502"
        sep: str = f"{reset}{v_line}"

        # Calculate visual width for complex Unicode characters (Emojis)
        # to ensure column alignment remains intact.
        visual_width: int = 0
        for char in extra_icon:
            cp: int = ord(char)
            if 0xFE00 <= cp <= 0xFE0F:
                continue
            visual_width += 2 if cp > 127 else 1

        if not extra_icon.strip():
            formatted_icon: str = "          "
        else:
            extra_padding: int = 1 if "\U0001f6e1" in extra_icon else 0
            padding: str = " " * (max(0, 10 - visual_width) + extra_padding)
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
C: Dict[str, str] = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "MAGENTA": "\033[95m",
    "BLUE": "\033[94m",
    "RESET": "\033[0m"
}

class Icons:
    """
    Static repository of Unicode icons used for inline certificate status signaling
    within the TrustChainBuilder and Renderers.
    """

    INFO: str = "\U0001f535"  # 🔵
    VALID: str = "\U00002705"  # ✅ (White Heavy Check Mark)
    EXPIRED: str = "\U0000274c"  # ❌ (Cross Mark)
    EXPIRING: str = "\U000023f3"  # ⏳
    WARNING: str = "\U00002757"  # ❗ (Warning Sign)
    LOCKED: str = "\U0001f512"  # 🔒 (Locked)
    BROKEN: str = "\U0001f4a5"  # 💥 (Broken Chain)
    UNKNOWN: str = "\U00002753"  # ❓ (Black Question Mark Ornament)
    AIA: str = "\U0001f310"  # 🌐 (Globe with Meridians)
    SYSTEM: str = "\U0001f4bb"  # 💻 (Laptop)
    COLLISION: str = "\U0001f46f"  # 👯
    OCSP_OK: str = "\U0001f6e1\ufe0f"  # 🛡️
    SIGNED: str = "\U00002611\ufe0f"  # ☑️
    UNCERTAIN: str = "\U00002754"  # ❔
    REVOKED: str = "\U0001f6ab"  # 🚫
    COMMENT: str = "\U0001f4ac"  # 💬

# Predefined Status Instances
ERROR: Status = Status("ERROR", Icons.EXPIRED, C["RED"])
OK: Status = Status("OK", Icons.VALID, C["GREEN"])
WARNING: Status = Status("WARNING", Icons.WARNING, C["YELLOW"])
EXPIRING: Status = Status("EXPIRING", Icons.EXPIRING, C["YELLOW"])
MISSING: Status = Status("MISSING", Icons.UNKNOWN, C["MAGENTA"], translate=False)
COLLISION: Status = Status("COLLISION", Icons.COLLISION, C["CYAN"], translate=False)
INFO: Status = Status("INFO", Icons.INFO, C["BLUE"])
SYSTEM: Status = Status("SYSTEM", Icons.SYSTEM, C["BLUE"], translate=False)
AIA: Status = Status("AIA", Icons.AIA, C["CYAN"], translate=False)
REVOKED: Status = Status("REVOKED", Icons.REVOKED, C["RED"])
