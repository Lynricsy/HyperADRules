from __future__ import annotations

import argparse
import http.client
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Final, cast

# provider 名 -> (behavior, 发布文件名)
PROVIDERS: Final[dict[str, tuple[str, str]]] = {
    "ads_domain": ("domain", "hyper_adrules_ads.mrs"),
    "ads_ipcidr": ("ipcidr", "hyper_adrules_ads_ipcidr.mrs"),
    "allow_domain": ("domain", "hyper_adrules_allow.mrs"),
    "allow_ipcidr": ("ipcidr", "hyper_adrules_allow_ipcidr.mrs"),
    "malware_domain": ("domain", "hyper_adrules_malware.mrs"),
    "malware_ipcidr": ("ipcidr", "hyper_adrules_malware_ipcidr.mrs"),
}
STARTUP_TIMEOUT_SECONDS: Final[float] = 60.0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start mihomo and initialize all published MRS rule providers.")
    _ = parser.add_argument("--dist", type=Path, required=True)
    _ = parser.add_argument("--mihomo", type=Path, required=True)
    return parser.parse_args(argv)


def build_config(controller_port: int) -> str:
    lines = [
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        f"external-controller: 127.0.0.1:{controller_port}",
        "rule-providers:",
    ]
    rules: list[str] = []
    for name, (behavior, filename) in PROVIDERS.items():
        lines.extend(
            [
                f"  {name}:",
                "    type: file",
                f"    behavior: {behavior}",
                "    format: mrs",
                f"    path: ./ruleset/{filename}",
            ],
        )
        suffix = ",no-resolve" if behavior == "ipcidr" else ""
        rules.append(f"  - RULE-SET,{name},REJECT{suffix}")
    lines.append("rules:")
    lines.extend(rules)
    lines.append("  - MATCH,DIRECT")
    return "\n".join(lines) + "\n"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return cast("int", sock.getsockname()[1])


def fetch_rule_providers(port: int, process: subprocess.Popen[bytes]) -> dict[str, object] | None:
    # mihomo 在 provider 全部 Initial 之后才启动 external-controller, 接口可用即加载完成。
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    url = f"http://127.0.0.1:{port}/providers/rules"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return None
        try:
            with cast("http.client.HTTPResponse", urllib.request.urlopen(url, timeout=2)) as response:
                payload = cast("dict[str, object]", json.loads(response.read()))
                return cast("dict[str, object]", payload["providers"])
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.2)
    return None


def find_problems(providers: dict[str, object], log_text: str) -> list[str]:
    problems = [line for line in log_text.splitlines() if "initial rule provider" in line and "error" in line]
    for name in PROVIDERS:
        info = providers.get(name)
        rule_count = cast("dict[str, object]", info).get("ruleCount") if isinstance(info, dict) else None
        # 发布的 MRS 均不为空集 (空 ipcidr 使用占位地址), 0 条即加载失败。
        if not isinstance(rule_count, int) or rule_count < 1:
            problems.append(f"provider {name} loaded {rule_count!r} rules")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    dist = cast("Path", args.dist)
    mihomo = cast("Path", args.mihomo)
    for _, filename in PROVIDERS.values():
        path = dist / filename
        if not path.is_file() or path.stat().st_size == 0:
            print(f"missing mrs asset: {path}", file=sys.stderr)
            return 1

    home = Path(tempfile.mkdtemp(prefix="mihomo-validate-"))
    try:
        ruleset_dir = home / "ruleset"
        _ = ruleset_dir.mkdir(parents=True)
        for _, filename in PROVIDERS.values():
            _ = shutil.copy2(dist / filename, ruleset_dir / filename)
        port = free_port()
        config_path = home / "config.yaml"
        _ = config_path.write_text(build_config(port), encoding="utf-8")
        log_path = home / "mihomo.log"
        with log_path.open("wb") as log_file:
            process = subprocess.Popen(  # noqa: S603 - trusted local mihomo binary
                [str(mihomo), "-d", str(home), "-f", str(config_path)],
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
            try:
                providers = fetch_rule_providers(port, process)
            finally:
                process.terminate()
                try:
                    _ = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _ = process.wait()
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if providers is None:
            print(log_text, end="", file=sys.stderr)
            print("mihomo external-controller did not become ready", file=sys.stderr)
            return 1
        problems = find_problems(providers, log_text)
        if problems:
            print(log_text, end="", file=sys.stderr)
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1
    finally:
        shutil.rmtree(home, ignore_errors=True)
    print("all mrs assets loaded successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
