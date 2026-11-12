from __future__ import annotations

from pathlib import Path
from typing import Final

from scripts.ruleset_formats import write_kind_text_formats
from scripts.ruleset_parser import as_ipcidr, parse_adguard_values
from scripts.ruleset_types import (
    ConversionResult,
    ConversionStats,
    RuleCollector,
    RuleKind,
    UpstreamKind,
    UpstreamSources,
)

COMMENT_PREFIXES: Final[tuple[str, ...]] = ("!", "#", "[")
EXCEPTION_PREFIX: Final[str] = "@@"
MIN_QUOTED_LENGTH: Final[int] = 2
OUTPUT_PREFIX: Final[str] = "hyper_adrules"

def convert_repositories(
    sources: UpstreamSources,
    upstream_commits: dict[UpstreamKind, str],
) -> ConversionResult:
    collectors: dict[RuleKind, RuleCollector] = {kind: RuleCollector() for kind in RuleKind}
    stats: dict[RuleKind, ConversionStats] = {kind: ConversionStats() for kind in RuleKind}

    parse_file(sources.goodbyeads_dns, RuleKind.ADS, collectors, stats)
    parse_file(sources.goodbyeads_allow, RuleKind.ALLOW, collectors, stats)
    parse_file(sources.urlhaus, RuleKind.MALWARE, collectors, stats)
    parse_user_rules(sources.adguard_magisk / "Adguardhome" / "bin" / "AdGuardHome.yaml", collectors, stats)
    parse_anti_ad(sources.anti_ad, collectors, stats)
    parse_coolapk_1007_reward(sources.coolapk_1007_reward, collectors, stats)
    # 本地白名单并入 allow; 不从 ads 删除上游条目, 客户端靠 allow/PASS 优先。
    parse_local_allow(sources.local_allow, collectors, stats)

    return ConversionResult(
        buckets={kind: collector.freeze() for kind, collector in collectors.items()},
        stats=stats,
        upstream_commits=upstream_commits,
    )

def parse_anti_ad(
    source_dir: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    parse_clash_payload_file(source_dir / "anti-ad-clash.yaml", RuleKind.ADS, collectors, stats)
    parse_file(source_dir / "anti-ad-adguard.txt", RuleKind.ALLOW, collectors, stats, exceptions_only=True)
    parse_clash_payload_file(source_dir / "anti-ad-white-for-clash.yaml", RuleKind.ALLOW, collectors, stats)

def parse_coolapk_1007_reward(
    source_path: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    parse_file(source_path, RuleKind.ADS, collectors, stats)


def parse_local_allow(
    source_path: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    # 仅接受 @@ 例外; 拦截规则不得经本地白名单文件混入 allow。
    parse_file(source_path, RuleKind.ALLOW, collectors, stats, exceptions_only=True)

def parse_file(
    path: Path,
    default_kind: RuleKind,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
    *,
    exceptions_only: bool = False,
) -> None:
    if not path.is_file():
        message = f"missing rule file: {path}"
        raise FileNotFoundError(message)
    with path.open("r", encoding="utf-8", errors="replace") as rule_file:
        for raw_line in rule_file:
            if exceptions_only and not raw_line.lstrip().startswith(EXCEPTION_PREFIX):
                continue
            parse_rule(raw_line.rstrip("\n"), default_kind, collectors, stats)

def parse_clash_payload_file(
    path: Path,
    default_kind: RuleKind,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    if not path.is_file():
        message = f"missing Clash payload file: {path}"
        raise FileNotFoundError(message)
    in_payload = False
    with path.open("r", encoding="utf-8", errors="replace") as rule_file:
        for raw_line in rule_file:
            line = raw_line.strip()
            if line == "payload:":
                in_payload = True
                continue
            if not in_payload or not line.startswith("- "):
                continue
            parse_clash_payload_value(unquote_yaml_list_value(line[2:]), default_kind, collectors, stats)

def parse_clash_payload_value(
    value: str,
    default_kind: RuleKind,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    stat = stats[default_kind]
    stat.total += 1
    if ipcidr := as_ipcidr(value):
        collectors[default_kind].add_ipcidr(ipcidr)
        stat.ipcidr += 1
        return
    collectors[default_kind].add_domain(value)
    stat.domain += 1

def parse_user_rules(
    config_path: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    if not config_path.is_file():
        message = f"missing AdGuardHome config: {config_path}"
        raise FileNotFoundError(message)
    in_user_rules = False
    with config_path.open("r", encoding="utf-8", errors="replace") as config_file:
        for raw_line in config_file:
            line = raw_line.rstrip("\n")
            if line == "user_rules:":
                in_user_rules = True
                continue
            if in_user_rules and line and not line.startswith("  - "):
                break
            if not in_user_rules or not line.startswith("  - "):
                continue
            parse_rule(unquote_yaml_list_value(line[4:]), RuleKind.ADS, collectors, stats)

def unquote_yaml_list_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= MIN_QUOTED_LENGTH and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= MIN_QUOTED_LENGTH and value[0] == '"' and value[-1] == '"':
        return bytes(value[1:-1], "utf-8").decode("unicode_escape")
    return value

def parse_rule(
    raw_line: str,
    default_kind: RuleKind,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    line = raw_line.strip()
    kind = RuleKind.ALLOW if line.startswith(EXCEPTION_PREFIX) else default_kind
    stat = stats[kind]
    stat.total += 1

    if not line or line.startswith(COMMENT_PREFIXES):
        stat.comments += 1
        return
    if line.startswith(EXCEPTION_PREFIX):
        line = line.removeprefix(EXCEPTION_PREFIX)

    parsed_values = parse_adguard_values(line, stat, allow_domain_modifier=kind is RuleKind.ALLOW)
    if not parsed_values:
        return

    for value in parsed_values:
        if ipcidr := as_ipcidr(value):
            collectors[kind].add_ipcidr(ipcidr)
            stat.ipcidr += 1
            continue
        collectors[kind].add_domain(value)
        stat.domain += 1

def write_outputs(result: ConversionResult, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for kind, buckets in result.buckets.items():
        _ = write_kind_text_formats(kind, buckets, output_dir)
    write_manifest(result, output_dir / "manifest.md")


def write_manifest(result: ConversionResult, path: Path) -> None:
    lines = [
        "# HyperADRules multi-format rulesets",
        "",
        "## 上游",
        "",
        f"- GOODBYEADS dns.txt: `{result.upstream_commits[UpstreamKind.GOODBYEADS_DNS]}`",
        f"- GOODBYEADS allow.txt: `{result.upstream_commits[UpstreamKind.GOODBYEADS_ALLOW]}`",
        f"- URLHaus (AdGuard filter_11): `{result.upstream_commits[UpstreamKind.URLHAUS]}`",
        f"- AdGuard Home For Magisk Mod user_rules: `{result.upstream_commits[UpstreamKind.ADGUARD_MAGISK]}`",
        f"- anti-AD: `{result.upstream_commits[UpstreamKind.ANTI_AD]}`",
        f"- dead-horse: `{result.upstream_commits[UpstreamKind.DEAD_HORSE]}`",
        f"- Coolapk 1007 reward: `{result.upstream_commits[UpstreamKind.COOLAPK_1007_REWARD]}`",
        "- local allow: `sources/local_allow.txt`",
        "",
        "- 产物语义: 多上游 DNS 广告规则到多种客户端格式的保守转换。",
        f"- 例外规则已拆为 `{OUTPUT_PREFIX}_allow.*`, mihomo 建议在 `sub-rules` 中用 `PASS`。",
        "- dnsmasq / SmartDNS 仅输出 ads、malware 的 suffix 阻断规则; exact 与 wildcard 不会静默扩大。",
        "- allow 不生成 dnsmasq / SmartDNS 阻断文件。",
        "",
        "| 集合 | domain | ipcidr | 跳过 | 正则 | 修饰符 | 路径 | 端口 | 模式 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for kind in RuleKind:
        stat = result.stats[kind]
        row = (
            f"| `{kind.value}` | {stat.domain} | {stat.ipcidr} | {stat.skipped} | "
            f"{stat.unsupported_regex} | {stat.unsupported_modifier} | {stat.unsupported_path} | "
            f"{stat.unsupported_port} | {stat.unsupported_pattern} |"
        )
        _ = lines.append(row)
    _ = lines.extend(
        [
            "",
            "## 规则集",
            "",
            f"- mihomo MRS: `{OUTPUT_PREFIX}_{{ads,allow,malware}}.mrs` / `*_ipcidr.mrs`",
            f"- Clash YAML: `{OUTPUT_PREFIX}_*_clash.yaml` / `*_clash_ipcidr.yaml`",
            "- domains / surge / surge2 / adguard / easylist / sing-box json",
            f"- dnsmasq / SmartDNS: 仅 `{OUTPUT_PREFIX}_{{ads,malware}}_*.conf`",
            f"- sing-box SRS: `{OUTPUT_PREFIX}_*_singbox.srs` (由 json 编译)",
        ],
    )
    _ = path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def print_summary(result: ConversionResult) -> None:
    for kind in RuleKind:
        stat = result.stats[kind]
        summary = (
            f"{kind.value}: domain={stat.domain} ipcidr={stat.ipcidr} skipped={stat.skipped} "
            f"regex={stat.unsupported_regex} modifier={stat.unsupported_modifier} "
            f"path={stat.unsupported_path} port={stat.unsupported_port} "
            f"pattern={stat.unsupported_pattern} total={stat.total}"
        )
        _ = print(summary)
