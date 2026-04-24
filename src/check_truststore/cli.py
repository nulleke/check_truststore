# -----------------------------------------------------------------------------
# TrustStore Analyzer & Visualizer
# -----------------------------------------------------------------------------
# Main Architect & Lead Developer: Serge van Thillo <nulleke76@gmail.com>
# Development Assistant: AI (Refactoring & Pydantic compatibility)
# Date: 2026
#
# Logic & Design:
# This tool was architected to analyze certificate truststores via YAML.
# The core logic for chain reconstruction and collision detection was
# designed by the Lead Developer. AI was used to assist with syntax
# optimization and cross-version Python support.
#
# Copyright (C) 2026 Serge van Thillo <nulleke76@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import argparse
import json
from pathlib import Path

from check_truststore.engine.core import (
    _,
    ERROR,
    WARNING,
    INFO,
    CertificateRepository,
    TrustStoreAnalyzer,
)
from check_truststore.providers import (
    YamlInputProvider,
    JsonInputProvider,
    SingleFileInputProvider,
    DirectoryInputProvider,
)
from check_truststore.renderers import TrustStoreRenderer


def main() -> None:
    _("ERROR")
    _("WARNING")
    _("OK")
    _("INFO")
    _("CHAIN")
    _("INVALID")
    _("EXPIRED")
    _("EXPIRING")
    _("SYSTEM")
    _("PARENT_NOT_A_CA")

    def valid_path(path_str: str) -> Path:
        path = Path(path_str)
        if not path.exists():
            raise argparse.ArgumentTypeError(
                _("Path '{path}' does not exist.").format(path=path_str)
            )
        return path

    parser = argparse.ArgumentParser(
        description=_(
            "Analyze certificate truststores and visualize the chain hierarchy."
        ),
        epilog=_("Compatible with Python 3.6+"),
        add_help=False,
    )
    parser.add_argument(
        "inputs", type=valid_path, nargs="+", help=_("Path to the input source(s)")
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help=_("Show this help message and exit"),
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "text", "status"],
        default="json",
        help=_("Output format"),
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", default=False, help=_("Show debug info")
    )
    parser.add_argument(
        "-s",
        "--system",
        action="store_true",
        default=False,
        help=_("Incorporate system truststore"),
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=30,
        help=_("Expiration threshold in days (default: 30)"),
    )
    parser.add_argument(
        "-a",
        "--show-san",
        action="store_true",
        help=_("Display Subject Alternative Names (SAN) in the tree view"),
    )

    args = parser.parse_args()

    analysis_groups = []
    repo = CertificateRepository(debug=args.debug)

    if args.debug:
        INFO.log(
            _("Starting analysis"),
            f"Inputs: {[p.name for p in args.inputs]}, System: {args.system}",
        )

    try:
        for path in args.inputs:
            provider = None

            if path.is_dir():
                provider = DirectoryInputProvider(path, repository=repo, recursive=True)
            elif path.suffix in [".yml", ".yaml"]:
                provider = YamlInputProvider(path, repository=repo, debug=args.debug)
            elif path.suffix == ".json":
                provider = JsonInputProvider(path, repository=repo, debug=args.debug)
            elif path.is_file():
                provider = SingleFileInputProvider(path, repository=repo)

            if provider:
                groups = provider.get_groups()
                if groups:
                    analysis_groups.extend(groups)
                elif args.debug:
                    WARNING.log(
                        path.name, _("No certificates found via this provider.")
                    )

        if len(analysis_groups) == 1 and not args.system:
            args.system = True

        if not analysis_groups:
            WARNING.log(_("No certificates found to display."))
            sys.exit(0)

        analyzer = TrustStoreAnalyzer(groups=analysis_groups, **vars(args))
        results = analyzer.analyze()

        renderer = TrustStoreRenderer()
        output = renderer.render(
            results, args.format, system=args.system, show_san=args.show_san
        )

        print(output)

        if args.format == "status":
            try:
                report = json.loads(output)
                sys.exit(report.get("metadata", {}).get("exitCode", 0))
            except (json.JSONDecodeError, KeyError, TypeError):
                sys.exit(7)

    except KeyboardInterrupt:
        sys.stderr.write("\n")
        INFO.log(_("Analysis interrupted by user"))
        sys.exit(130)

    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        ERROR.log(_("An unexpected error occurred"), error_msg)
        if args.debug:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
