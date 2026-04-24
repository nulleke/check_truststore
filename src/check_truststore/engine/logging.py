"""
TrustStore Analyzer & Visualizer - LOGGING MODULE
Architect: Serge van Thillo

This module provides high-level terminal logging with support for internationalization (i18n),
ANSI color-coded output, and Unicode iconography. It is designed to output primarily to
stderr to keep stdout clean for data redirection (JSON/XML).
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
        reset = "\033[0m"
        v_line = "\u2502"
        sep = f"{reset}{v_line}"

        # Calculate visual width for complex Unicode characters (Emojis)
        # to ensure column alignment remains intact.
        clean_icons = extra_icon.strip()
        visual_width = 0
        for char in clean_icons:
            visual_width += 2 if ord(char) > 127 else 1

        padding = " " * max(0, 8 - visual_width)
        formatted_icon = f" {clean_icons}{padding}"

        prefix = "{}{} {:<14} {} {} {} {}{:<60} {}{} ".format(
            self.COLOR,
            self.ICON,
            display_label,
            sep,
            formatted_icon,
            sep,
            self.COLOR,
            message[:60],
            sep,
            self.COLOR,
        )

        sys.stderr.write("{}{}{}\n".format(prefix, detail, reset))


# ANSI Color Constants
RED, GREEN, YELLOW, CYAN, MAGENTA, BLUE = (
    "\033[91m",
    "\033[92m",
    "\033[93m",
    "\033[96m",
    "\033[95m",
    "\033[94m",
)

# Predefined Status Instances
ERROR = Status("ERROR", "\U0000274c", RED)  # ❌
OK = Status("OK", "\U00002705", GREEN)  # ✅
WARNING = Status("WARNING", "\U000023f3", YELLOW)  # ⏳
MISSING = Status("MISSING", "\U00002753", MAGENTA, translate=False)  # ❓
COLLISION = Status("COLLISION", "\U0001f46f", CYAN, translate=False)  # 👯
INFO = Status("INFO", "\U0001f535", BLUE)  # 🔵
SYSTEM = Status("SYSTEM", "\U0001f4bb", BLUE, translate=False)  # 💻


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
