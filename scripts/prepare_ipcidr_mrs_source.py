from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

from scripts.ruleset_mrs import EMPTY_IPCIDR_MRS_PLACEHOLDER_CIDR, write_ipcidr_mrs_source


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write the ipcidr text source for mihomo convert-ruleset.")
    _ = parser.add_argument("--text", type=Path, required=True)
    _ = parser.add_argument("--source", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    text_path = cast("Path", args.text)
    source_path = cast("Path", args.source)
    if write_ipcidr_mrs_source(text_path, source_path):
        print(f"{text_path.name}: empty, mrs uses placeholder {EMPTY_IPCIDR_MRS_PLACEHOLDER_CIDR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
