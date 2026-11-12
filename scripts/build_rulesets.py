#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from scripts.ruleset_core import convert_repositories, print_summary, write_outputs
from scripts.ruleset_types import UpstreamKind, UpstreamSources

# CLI 选项名 (去掉 -source / -commit 后缀) 与上游的对应关系; 每个上游都必须给出本地路径与版本标识。
UPSTREAM_OPTIONS: Final[dict[UpstreamKind, str]] = {
    UpstreamKind.ADGUARD_MAGISK: "adguard",
    UpstreamKind.GOODBYEADS_DNS: "goodbyeads-dns",
    UpstreamKind.GOODBYEADS_ALLOW: "goodbyeads-allow",
    UpstreamKind.URLHAUS: "urlhaus",
    UpstreamKind.ANTI_AD: "anti-ad",
    UpstreamKind.COOLAPK_1007_REWARD: "coolapk-1007-reward",
}


@dataclass(frozen=True, slots=True)
class BuildArgs:
    sources: UpstreamSources
    output: Path
    upstream_commits: dict[UpstreamKind, str]


def parse_args(argv: Sequence[str]) -> BuildArgs:
    parser = argparse.ArgumentParser(description="Build mihomo rule-provider text sources.")
    for option in UPSTREAM_OPTIONS.values():
        _ = parser.add_argument(f"--{option}-source", type=Path, required=True)
    _ = parser.add_argument(
        "--local-allow-source",
        type=Path,
        default=Path("sources/local_allow.txt"),
        help="repo-local AdGuard exception rules merged into allow",
    )
    _ = parser.add_argument("--output", type=Path, required=True)
    for option in UPSTREAM_OPTIONS.values():
        _ = parser.add_argument(f"--{option}-commit", default="unknown")
    # dead-horse 白名单由 CI 下载进 anti-AD 目录, 只有版本标识没有独立路径。
    _ = parser.add_argument("--dead-horse-commit", default="unknown")
    parsed: dict[str, object] = vars(parser.parse_args(argv))

    def path_arg(name: str) -> Path:
        value = parsed[name.replace("-", "_")]
        if not isinstance(value, Path):
            raise TypeError(name)
        return value

    def str_arg(name: str) -> str:
        value = parsed[name.replace("-", "_")]
        if not isinstance(value, str):
            raise TypeError(name)
        return value

    commits = {kind: str_arg(f"{option}-commit") for kind, option in UPSTREAM_OPTIONS.items()}
    commits[UpstreamKind.DEAD_HORSE] = str_arg("dead-horse-commit")
    return BuildArgs(
        sources=UpstreamSources(
            adguard_magisk=path_arg("adguard-source"),
            goodbyeads_dns=path_arg("goodbyeads-dns-source"),
            goodbyeads_allow=path_arg("goodbyeads-allow-source"),
            urlhaus=path_arg("urlhaus-source"),
            anti_ad=path_arg("anti-ad-source"),
            coolapk_1007_reward=path_arg("coolapk-1007-reward-source"),
            local_allow=path_arg("local-allow-source"),
        ),
        output=path_arg("output"),
        upstream_commits=commits,
    )


def main() -> int:
    args = parse_args(sys.argv[1:])
    result = convert_repositories(args.sources, args.upstream_commits)
    write_outputs(result, args.output)
    print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
