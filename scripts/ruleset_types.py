from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class RuleKind(StrEnum):
    ADS = "ads"
    ALLOW = "allow"
    MALWARE = "malware"


class UpstreamKind(StrEnum):
    ADGUARD_MAGISK = "adguard-magisk"
    GOODBYEADS_DNS = "goodbyeads-dns"
    GOODBYEADS_ALLOW = "goodbyeads-allow"
    URLHAUS = "urlhaus"
    ANTI_AD = "anti-ad"
    DEAD_HORSE = "dead-horse"
    COOLAPK_1007_REWARD = "coolapk-1007-reward"


@dataclass(frozen=True, slots=True)
class UpstreamSources:
    # 本地已下载的上游路径; 目录型上游为仓库根, 其余为单个规则文件。
    # Magisk Mod 仓库根, 只取 AdGuardHome.yaml 的 user_rules; 其 data/filters 为手动上传的过期快照, 不再使用。
    adguard_magisk: Path
    goodbyeads_dns: Path
    goodbyeads_allow: Path
    urlhaus: Path
    anti_ad: Path
    coolapk_1007_reward: Path
    local_allow: Path


@dataclass(frozen=True, slots=True)
class RuleBuckets:
    domains: frozenset[str] = frozenset()
    ipcidrs: frozenset[str] = frozenset()


@dataclass(slots=True)
class RuleCollector:
    domains: set[str] = field(default_factory=set)
    ipcidrs: set[str] = field(default_factory=set)

    def add_domain(self, domain: str) -> None:
        self.domains.add(domain)

    def add_ipcidr(self, ipcidr: str) -> None:
        self.ipcidrs.add(ipcidr)

    def freeze(self) -> RuleBuckets:
        return RuleBuckets(domains=frozenset(self.domains), ipcidrs=frozenset(self.ipcidrs))


@dataclass(slots=True)
class ConversionStats:
    total: int = 0
    domain: int = 0
    ipcidr: int = 0
    comments: int = 0
    skipped: int = 0
    unsupported_regex: int = 0
    unsupported_modifier: int = 0
    unsupported_path: int = 0
    unsupported_port: int = 0
    unsupported_pattern: int = 0


@dataclass(frozen=True, slots=True)
class ConversionResult:
    buckets: dict[RuleKind, RuleBuckets]
    stats: dict[RuleKind, ConversionStats]
    upstream_commits: dict[UpstreamKind, str]
