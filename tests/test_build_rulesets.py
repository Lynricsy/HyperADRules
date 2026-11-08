from __future__ import annotations

import json
from pathlib import Path

from scripts.ruleset_core import convert_repositories, parse_rule, write_outputs
from scripts.ruleset_domain import DomainMatchKind, classify_domain, to_domain_regex
from scripts.ruleset_formats import write_kind_text_formats
from scripts.ruleset_mrs import EMPTY_IPCIDR_MRS_PLACEHOLDER_CIDR, write_ipcidr_mrs_source
from scripts.ruleset_parser import parse_adguard_values
from scripts.ruleset_stats import build_stats_payload, count_lines, expected_release_assets, release_assets_complete
from scripts.ruleset_types import (
    ConversionStats,
    RuleBuckets,
    RuleCollector,
    RuleKind,
    UpstreamKind,
)


def empty_local_allow(tmp_path: Path) -> Path:
    path = tmp_path / "local_allow.txt"
    _ = path.write_text("# empty local allow\n", encoding="utf-8")
    return path


def test_parse_domain_block_rule_when_adguard_suffix_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||Example.COM^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.example.com"}
    assert stats[RuleKind.ADS].domain == 1


def test_parse_allow_rule_when_exception_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@||safe.example.com^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"+.safe.example.com"}
    assert collectors[RuleKind.ADS].domains == set()


def test_parse_hosts_block_rule_when_sinkhole_entry() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("0.0.0.0 ads.example.com", RuleKind.ADS, collectors, stats)
    parse_rule("127.0.0.1 localhost", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"ads.example.com"}
    assert stats[RuleKind.ADS].domain == 1


def test_parse_hosts_block_rule_when_inline_comment_has_domain_text() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("0.0.0.0 ads.example.com # note.example.com", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"ads.example.com"}


def test_parse_ip_rule_when_ipv4_literal() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||203.0.113.1^", RuleKind.MALWARE, collectors, stats)

    assert collectors[RuleKind.MALWARE].ipcidrs == {"203.0.113.1/32"}


def test_parse_ipcidr_rule_when_cidr_literal() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||216.239.35.0/24^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].ipcidrs == {"216.239.35.0/24"}


def test_skip_block_rule_when_host_has_path() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}
    path_rule_count = 2

    parse_rule("||claude.ai/sentry^", RuleKind.ADS, collectors, stats)
    parse_rule("||example.com/path.js^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == set()
    assert stats[RuleKind.ADS].unsupported_path == path_rule_count
    assert "+.claude.ai" not in collectors[RuleKind.ADS].domains


def test_skip_allow_rule_when_path_contains_url() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@||ib.adnxs.com/getuid?http://*.pch.com/", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_path == 1


def test_skip_allow_rule_when_rule_starts_with_scheme_relative_url_path() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@://www.fedex.com/Tracking?", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_path == 1


def test_parse_allow_domain_when_rule_starts_with_blob_url_host_only() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@|blob:https://www.twitch.tv", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"www.twitch.tv"}


def test_skip_allow_rule_when_exception_with_http_url_modifier() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@https://media.amazon.map.fastly.net^$script", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_modifier == 1


def test_skip_allow_rule_when_exception_with_websocket_url_modifier() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@ws://localhost^$stealth,domain=play.sooplive.co.kr", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_modifier == 1


def test_skip_block_rule_when_host_has_port() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}
    port_rule_count = 2

    parse_rule("||ad.example.com:8443^", RuleKind.ADS, collectors, stats)
    parse_rule("||example.com:8443^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == set()
    assert stats[RuleKind.ADS].unsupported_port == port_rule_count


def test_skip_block_rule_when_url_has_invalid_port() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}
    invalid_port_rule_count = 2

    parse_rule("@@https://example.com:99999^", RuleKind.ADS, collectors, stats)
    parse_rule("@@https://example.com:abc^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_port == invalid_port_rule_count


def test_skip_block_rule_when_host_has_query_or_fragment() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}
    query_fragment_rule_count = 3

    parse_rule("||example.com?x=1^", RuleKind.ADS, collectors, stats)
    parse_rule("||example.com#section^", RuleKind.ADS, collectors, stats)
    parse_rule("||example.com/^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == set()
    assert stats[RuleKind.ADS].unsupported_path == query_fragment_rule_count

def test_parse_domain_rule_when_safe_wildcard_suffix_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||ads*-normal*.zijieapi.com^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.ads*-normal*.zijieapi.com"}


def test_parse_domain_rule_when_wildcard_label_suffix_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||xbox.*.microsoft.com^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.xbox.*.microsoft.com"}


def test_skip_allow_rule_when_exception_with_modifier_has_host() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@||cdn.example.com/path.js$script,domain=site.example", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_modifier == 1

def test_skip_allow_rule_when_domain_modifier_has_no_host() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@*$script,domain=example.com", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_modifier == 1


def test_skip_rule_when_pure_path_specific_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("/path-only.js", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == set()
    assert stats[RuleKind.ADS].unsupported_path == 1


def test_skip_rule_when_dns_modifier_cannot_be_represented_by_mrs() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||example.com^$dnstype=AAAA", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == set()
    assert stats[RuleKind.ADS].unsupported_modifier == 1


def test_parse_adguard_values_when_domain_modifier_not_allowed() -> None:
    stat = ConversionStats()

    values = parse_adguard_values("*$domain=example.com", stat, allow_domain_modifier=False)

    assert values == ()
    assert stat.unsupported_modifier == 1


def test_convert_repositories_when_multiple_upstreams_have_rules(tmp_path: Path) -> None:
    adguard_source = tmp_path / "adguard"
    anti_ad_source = tmp_path / "anti-ad"
    reward_source = tmp_path / "reward.txt"
    filters_dir = adguard_source / "Adguardhome" / "bin" / "data" / "filters"
    filters_dir.mkdir(parents=True)
    (adguard_source / "Adguardhome" / "bin").mkdir(exist_ok=True)
    _ = (filters_dir / "1721861846.txt").write_text("||ads.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1735560833.txt").write_text("||bad.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1721861844.txt").write_text("@@||safe.example.com^\n", encoding="utf-8")
    _ = (adguard_source / "Adguardhome" / "bin" / "AdGuardHome.yaml").write_text(
        "user_rules:\n  - '||custom.example.com^'\n",
        encoding="utf-8",
    )
    anti_ad_source.mkdir()
    _ = (anti_ad_source / "anti-ad-adguard.txt").write_text(
        "@@||anti-safe.example.com^\n||ads.example.com^\n||anti.example.com^\n",
        encoding="utf-8",
    )
    _ = (anti_ad_source / "anti-ad-clash.yaml").write_text(
        "payload:\n  - '+.anti-clash.example.com'\n  - '203.0.113.9/32'\n",
        encoding="utf-8",
    )
    _ = (anti_ad_source / "anti-ad-white-for-clash.yaml").write_text(
        "payload:\n  - '+.anti-white.example.com'\n  - '198.51.100.10/32'\n",
        encoding="utf-8",
    )
    _ = reward_source.write_text(
        "#@coolapk 1007\n127.0.0.1 localhost\n0.0.0.0 reward.example.com\n",
        encoding="utf-8",
    )

    result = convert_repositories(
        adguard_source,
        anti_ad_source,
        reward_source,
        {
            UpstreamKind.ADGUARD_MAGISK: "adguard-sha",
            UpstreamKind.ANTI_AD: "anti-sha",
            UpstreamKind.DEAD_HORSE: "dead-horse-sha256",
            UpstreamKind.COOLAPK_1007_REWARD: "reward-sha256",
        },
        local_allow_source=empty_local_allow(tmp_path),
    )

    assert result.buckets[RuleKind.ADS].domains == {
        "+.ads.example.com",
        "+.anti-clash.example.com",
        "+.custom.example.com",
        "reward.example.com",
    }
    assert result.buckets[RuleKind.ADS].ipcidrs == {"203.0.113.9/32"}
    assert result.buckets[RuleKind.ALLOW].domains == {
        "+.anti-safe.example.com",
        "+.anti-white.example.com",
        "+.safe.example.com",
    }
    assert result.buckets[RuleKind.ALLOW].ipcidrs == {"198.51.100.10/32"}
    assert result.buckets[RuleKind.MALWARE].domains == {"+.bad.example.com"}
    assert result.upstream_commits[UpstreamKind.ADGUARD_MAGISK] == "adguard-sha"
    assert result.upstream_commits[UpstreamKind.ANTI_AD] == "anti-sha"
    assert result.upstream_commits[UpstreamKind.DEAD_HORSE] == "dead-horse-sha256"
    assert result.upstream_commits[UpstreamKind.COOLAPK_1007_REWARD] == "reward-sha256"


def test_build_stats_payload_when_release_assets_exist(tmp_path: Path) -> None:
    ads_domain_count = 2
    ads_ipcidr_count = 1
    total_rule_count = 5
    ads_mrs_bytes = 1536

    _ = (tmp_path / "hyper_adrules_ads.txt").write_text("+.ads.example\n+.ads-two.example\n", encoding="utf-8")
    _ = (tmp_path / "hyper_adrules_ads_ipcidr.txt").write_text("203.0.113.1/32\n", encoding="utf-8")
    _ = (tmp_path / "hyper_adrules_allow.txt").write_text("+.safe.example\n", encoding="utf-8")
    _ = (tmp_path / "hyper_adrules_allow_ipcidr.txt").write_text("", encoding="utf-8")
    _ = (tmp_path / "hyper_adrules_malware.txt").write_text("+.bad.example\n", encoding="utf-8")
    _ = (tmp_path / "hyper_adrules_malware_ipcidr.txt").write_text("", encoding="utf-8")
    _ = (tmp_path / "hyper_adrules_ads.mrs").write_bytes(b"a" * ads_mrs_bytes)
    _ = (tmp_path / "hyper_adrules_ads_ipcidr.mrs").write_bytes(b"ip")
    _ = (tmp_path / "hyper_adrules_allow.mrs").write_bytes(b"allow")
    _ = (tmp_path / "hyper_adrules_malware.mrs").write_bytes(b"malware")

    payload = build_stats_payload(tmp_path)

    assert payload["rules"]["ads"]["domains"] == ads_domain_count
    assert payload["rules"]["ads"]["ipcidrs"] == ads_ipcidr_count
    assert payload["totals"]["total"] == total_rule_count
    assert payload["badges"] == {
        "ads_domains": "2",
        "allow_domains": "1",
        "malware_domains": "1",
        "total_rules": "5",
        "ads_mrs_size": "2 KiB",
    }
    assert payload["mrs"]["ads"]["bytes"] == ads_mrs_bytes
    assert "allow_ipcidr" not in payload["mrs"]




def test_count_lines_ignores_comment_only_ipcidr_placeholder(tmp_path: Path) -> None:
    path = tmp_path / "hyper_adrules_allow_ipcidr.txt"
    _ = path.write_text("# empty ipcidr ruleset\n", encoding="utf-8")
    assert count_lines(path) == 0


def test_ipcidr_mrs_source_uses_placeholder_only_for_comment_only_text(tmp_path: Path) -> None:
    empty_text = tmp_path / "allow_ipcidr.txt"
    rules_text = tmp_path / "ads_ipcidr.txt"
    _ = empty_text.write_text("# empty ipcidr ruleset\n", encoding="utf-8")
    _ = rules_text.write_text("# header\n1.2.3.4/32\n", encoding="utf-8")

    assert write_ipcidr_mrs_source(empty_text, tmp_path / "empty.src")
    assert (tmp_path / "empty.src").read_text(encoding="utf-8") == f"{EMPTY_IPCIDR_MRS_PLACEHOLDER_CIDR}\n"
    assert not write_ipcidr_mrs_source(rules_text, tmp_path / "rules.src")
    assert (tmp_path / "rules.src").read_text(encoding="utf-8") == "# header\n1.2.3.4/32\n"


def test_write_kind_text_formats_emits_empty_allow_ipcidr_assets(tmp_path: Path) -> None:
    buckets = RuleBuckets(domains=frozenset({"+.safe.example.com"}))
    _ = write_kind_text_formats(RuleKind.ALLOW, buckets, tmp_path)

    ipcidr_txt = (tmp_path / "hyper_adrules_allow_ipcidr.txt").read_text(encoding="utf-8")
    assert ipcidr_txt.startswith("#")
    assert count_lines(tmp_path / "hyper_adrules_allow_ipcidr.txt") == 0
    clash_ip = (tmp_path / "hyper_adrules_allow_clash_ipcidr.yaml").read_text(encoding="utf-8")
    assert "(ipcidr)" in clash_ip
    assert "payload:" in clash_ip
    assert "[]" in clash_ip

def test_expected_release_assets_includes_checksum_file_itself() -> None:
    checksum_text = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  dist/hyper_adrules_ads.txt\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  dist/manifest.md\n"
    )

    assets = expected_release_assets(checksum_text)

    assert assets == frozenset({"hyper_adrules_ads.txt", "manifest.md", "SHA256SUMS"})


def test_release_assets_complete_when_remote_matches_checksum_and_names() -> None:
    checksum_text = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  hyper_adrules_ads.txt\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  manifest.md\n"
    )
    remote_names = {"hyper_adrules_ads.txt", "manifest.md", "SHA256SUMS"}

    assert release_assets_complete(
        local_checksum_text=checksum_text,
        remote_checksum_text=checksum_text,
        remote_asset_names=remote_names,
    )


def test_release_assets_incomplete_when_checksum_file_missing_from_remote() -> None:
    checksum_text = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  hyper_adrules_ads.txt\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  manifest.md\n"
    )
    remote_names = {"hyper_adrules_ads.txt", "manifest.md"}

    assert not release_assets_complete(
        local_checksum_text=checksum_text,
        remote_checksum_text=checksum_text,
        remote_asset_names=remote_names,
    )


def test_classify_domain_when_exact_suffix_subdomain_and_wildcard() -> None:
    exact = classify_domain("exact.example.com")
    suffix = classify_domain("+.example.com")
    subdomain = classify_domain(".example.com")
    wildcard = classify_domain("+.ads*-normal.example.com")

    assert exact.kind is DomainMatchKind.EXACT
    assert exact.value == "exact.example.com"
    assert suffix.kind is DomainMatchKind.SUFFIX
    assert suffix.value == "example.com"
    assert subdomain.kind is DomainMatchKind.SUBDOMAIN
    assert subdomain.value == "example.com"
    assert wildcard.kind is DomainMatchKind.WILDCARD
    assert to_domain_regex(subdomain) == r"^.+\.example\.com$"
    assert to_domain_regex(suffix) == r"^(?:.+\.)?example\.com$"


def test_write_kind_text_formats_preserves_mihomo_semantics(tmp_path: Path) -> None:
    buckets = RuleBuckets(
        domains=frozenset(
            {
                "exact.example.com",
                "+.suffix.example.com",
                ".sub.example.com",
                "+.ads*-wild.example.com",
            },
        ),
        ipcidrs=frozenset({"203.0.113.1/32"}),
    )

    stats = write_kind_text_formats(RuleKind.ADS, buckets, tmp_path)

    mihomo = (tmp_path / "hyper_adrules_ads.txt").read_text(encoding="utf-8").splitlines()
    assert "exact.example.com" in mihomo
    assert "+.suffix.example.com" in mihomo
    assert ".sub.example.com" in mihomo
    assert "+.ads*-wild.example.com" in mihomo
    assert "+.sub.example.com" not in mihomo

    clash_domain = (tmp_path / "hyper_adrules_ads_clash.yaml").read_text(encoding="utf-8")
    assert "203.0.113.1/32" not in clash_domain
    assert ".sub.example.com" in clash_domain
    clash_ip = (tmp_path / "hyper_adrules_ads_clash_ipcidr.yaml").read_text(encoding="utf-8")
    assert "203.0.113.1/32" in clash_ip
    assert "exact.example.com" not in clash_ip

    domains_txt = (tmp_path / "hyper_adrules_ads_domains.txt").read_text(encoding="utf-8").splitlines()
    assert domains_txt == ["exact.example.com", "suffix.example.com"]

    surge = (tmp_path / "hyper_adrules_ads_surge.txt").read_text(encoding="utf-8").splitlines()
    assert "DOMAIN,exact.example.com" in surge
    assert "DOMAIN-SUFFIX,suffix.example.com" in surge
    assert "DOMAIN-WILDCARD,*.sub.example.com" in surge
    assert "IP-CIDR,203.0.113.1/32" in surge

    surge2 = (tmp_path / "hyper_adrules_ads_surge2.txt").read_text(encoding="utf-8").splitlines()
    assert "exact.example.com" in surge2
    assert ".suffix.example.com" in surge2
    assert ".sub.example.com" not in surge2

    dnsmasq = (tmp_path / "hyper_adrules_ads_dnsmasq.conf").read_text(encoding="utf-8").splitlines()
    assert dnsmasq == ["address=/suffix.example.com/"]

    smartdns = (tmp_path / "hyper_adrules_ads_smartdns.conf").read_text(encoding="utf-8").splitlines()
    assert smartdns == ["address /suffix.example.com/#"]

    adguard = (tmp_path / "hyper_adrules_ads_adguard.txt").read_text(encoding="utf-8").splitlines()
    assert "exact.example.com" in adguard
    assert "||suffix.example.com^" in adguard
    assert "/^.+\\.sub\\.example\\.com$/" in adguard
    assert all("ads*-wild" not in line for line in adguard)

    payload = json.loads((tmp_path / "hyper_adrules_ads_singbox.json").read_text(encoding="utf-8"))
    rule = payload["rules"][0]
    assert rule["domain"] == ["exact.example.com"]
    assert rule["domain_suffix"] == ["suffix.example.com"]
    assert r"^.+\.sub\.example\.com$" in rule["domain_regex"]
    assert r"^(?:.+\.)?ads.*-wild\.example\.com$" in rule["domain_regex"]
    assert rule["ip_cidr"] == ["203.0.113.1/32"]
    assert stats.domains_skipped_wildcard == 1
    assert stats.domains_subdomain == 1


def test_write_kind_text_formats_skips_allow_dns_sinkhole(tmp_path: Path) -> None:
    buckets = RuleBuckets(domains=frozenset({"+.safe.example.com", "exact.safe.example.com"}))
    _ = write_kind_text_formats(RuleKind.ALLOW, buckets, tmp_path)

    assert not (tmp_path / "hyper_adrules_allow_dnsmasq.conf").exists()
    assert not (tmp_path / "hyper_adrules_allow_smartdns.conf").exists()
    adguard = (tmp_path / "hyper_adrules_allow_adguard.txt").read_text(encoding="utf-8").splitlines()
    assert "@@||safe.example.com^" in adguard
    assert "@@exact.safe.example.com" in adguard


def test_write_kind_text_formats_keeps_empty_clash_ipcidr(tmp_path: Path) -> None:
    buckets = RuleBuckets(domains=frozenset({"+.bad.example.com"}))

    _ = write_kind_text_formats(RuleKind.MALWARE, buckets, tmp_path)

    empty_ip = (tmp_path / "hyper_adrules_malware_clash_ipcidr.yaml").read_text(encoding="utf-8")
    assert "(ipcidr)" in empty_ip
    assert "payload:" in empty_ip
    assert "[]" in empty_ip
    assert "- " not in empty_ip
    assert (tmp_path / "hyper_adrules_malware_ipcidr.txt").read_text(encoding="utf-8").startswith("#")
    assert (tmp_path / "hyper_adrules_malware_clash.yaml").is_file()


def test_write_outputs_emits_multi_format_files(tmp_path: Path) -> None:
    adguard_source = tmp_path / "adguard"
    anti_ad_source = tmp_path / "anti-ad"
    reward_source = tmp_path / "reward.txt"
    filters_dir = adguard_source / "Adguardhome" / "bin" / "data" / "filters"
    filters_dir.mkdir(parents=True)
    (adguard_source / "Adguardhome" / "bin").mkdir(exist_ok=True)
    _ = (filters_dir / "1721861846.txt").write_text(
        "||ads.example.com^\nexact.example.com\n",
        encoding="utf-8",
    )
    _ = (filters_dir / "1735560833.txt").write_text("||bad.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1721861844.txt").write_text("@@||safe.example.com^\n", encoding="utf-8")
    _ = (adguard_source / "Adguardhome" / "bin" / "AdGuardHome.yaml").write_text(
        "user_rules:\n  - '||custom.example.com^'\n",
        encoding="utf-8",
    )
    anti_ad_source.mkdir()
    _ = (anti_ad_source / "anti-ad-adguard.txt").write_text("@@||anti-safe.example.com^\n", encoding="utf-8")
    _ = (anti_ad_source / "anti-ad-clash.yaml").write_text(
        "payload:\n  - '+.anti-clash.example.com'\n  - '.subonly.example.com'\n  - '203.0.113.9/32'\n",
        encoding="utf-8",
    )
    _ = (anti_ad_source / "anti-ad-white-for-clash.yaml").write_text(
        "payload:\n  - '+.anti-white.example.com'\n",
        encoding="utf-8",
    )
    _ = reward_source.write_text("0.0.0.0 reward.example.com\n", encoding="utf-8")

    result = convert_repositories(
        adguard_source,
        anti_ad_source,
        reward_source,
        {
            UpstreamKind.ADGUARD_MAGISK: "adguard-sha",
            UpstreamKind.ANTI_AD: "anti-sha",
            UpstreamKind.DEAD_HORSE: "dead-horse-sha256",
            UpstreamKind.COOLAPK_1007_REWARD: "reward-sha256",
        },
        local_allow_source=empty_local_allow(tmp_path),
    )
    out = tmp_path / "dist"
    write_outputs(result, out)

    ads_txt = (out / "hyper_adrules_ads.txt").read_text(encoding="utf-8").splitlines()
    assert ".subonly.example.com" in ads_txt
    assert "+.subonly.example.com" not in ads_txt
    assert (out / "hyper_adrules_ads_singbox.json").is_file()
    assert (out / "hyper_adrules_ads_clash.yaml").is_file()
    assert (out / "hyper_adrules_ads_clash_ipcidr.yaml").is_file()
    assert (out / "hyper_adrules_ads_dnsmasq.conf").is_file()
    assert not (out / "hyper_adrules_allow_dnsmasq.conf").exists()
    assert "sing-box" in (out / "manifest.md").read_text(encoding="utf-8")


def test_dns_safe_build_does_not_contain_claude_apex(tmp_path: Path) -> None:
    adguard_source = tmp_path / "adguard"
    anti_ad_source = tmp_path / "anti-ad"
    reward_source = tmp_path / "reward.txt"
    filters_dir = adguard_source / "Adguardhome" / "bin" / "data" / "filters"
    filters_dir.mkdir(parents=True)
    (adguard_source / "Adguardhome" / "bin").mkdir(exist_ok=True)
    _ = (filters_dir / "1721861846.txt").write_text(
        "||claude.ai/sentry^\n||ads.example.com^\n",
        encoding="utf-8",
    )
    _ = (filters_dir / "1735560833.txt").write_text("||bad.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1721861844.txt").write_text("@@||safe.example.com^\n", encoding="utf-8")
    _ = (adguard_source / "Adguardhome" / "bin" / "AdGuardHome.yaml").write_text(
        "user_rules:\n  - '||custom.example.com^'\n",
        encoding="utf-8",
    )
    anti_ad_source.mkdir()
    _ = (anti_ad_source / "anti-ad-adguard.txt").write_text("@@||anti-safe.example.com^\n", encoding="utf-8")
    _ = (anti_ad_source / "anti-ad-clash.yaml").write_text(
        "payload:\n  - '+.anti-clash.example.com'\n",
        encoding="utf-8",
    )
    _ = (anti_ad_source / "anti-ad-white-for-clash.yaml").write_text(
        "payload:\n  - '+.anti-white.example.com'\n",
        encoding="utf-8",
    )
    _ = reward_source.write_text("0.0.0.0 reward.example.com\n", encoding="utf-8")

    result = convert_repositories(
        adguard_source,
        anti_ad_source,
        reward_source,
        {
            UpstreamKind.ADGUARD_MAGISK: "adguard-sha",
            UpstreamKind.ANTI_AD: "anti-sha",
            UpstreamKind.DEAD_HORSE: "dead-horse-sha256",
            UpstreamKind.COOLAPK_1007_REWARD: "reward-sha256",
        },
        local_allow_source=empty_local_allow(tmp_path),
    )
    out = tmp_path / "dist"
    write_outputs(result, out)

    assert "+.claude.ai" not in result.buckets[RuleKind.ADS].domains
    assert "claude.ai" not in result.buckets[RuleKind.ADS].domains
    assert result.stats[RuleKind.ADS].unsupported_path >= 1

    forbidden_tokens = ("+.claude.ai", "||claude.ai^", "DOMAIN-SUFFIX,claude.ai", "address=/claude.ai/")
    ads_text_files = (
        "hyper_adrules_ads.txt",
        "hyper_adrules_ads_clash.yaml",
        "hyper_adrules_ads_domains.txt",
        "hyper_adrules_ads_surge.txt",
        "hyper_adrules_ads_surge2.txt",
        "hyper_adrules_ads_dnsmasq.conf",
        "hyper_adrules_ads_smartdns.conf",
        "hyper_adrules_ads_adguard.txt",
        "hyper_adrules_ads_easylist.txt",
        "hyper_adrules_ads_singbox.json",
    )
    for relative_name in ads_text_files:
        content = (out / relative_name).read_text(encoding="utf-8")
        assert all(token not in content for token in forbidden_tokens)
        assert "claude.ai" not in content

def test_local_allow_covers_volces_business_domain(tmp_path: Path) -> None:
    """Issue #24: keep ads +.volces.com while allowlisting business hosts."""
    adguard_source = tmp_path / "adguard"
    anti_ad_source = tmp_path / "anti-ad"
    reward_source = tmp_path / "reward.txt"
    local_allow = tmp_path / "local_allow.txt"
    filters_dir = adguard_source / "Adguardhome" / "bin" / "data" / "filters"
    filters_dir.mkdir(parents=True)
    (adguard_source / "Adguardhome" / "bin").mkdir(exist_ok=True)
    _ = (filters_dir / "1721861846.txt").write_text("||ads.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1735560833.txt").write_text("||bad.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1721861844.txt").write_text("@@||safe.example.com^\n", encoding="utf-8")
    # Magisk user_rules 整域拦截 volces.com, 同时含拼写错误的 Kimi 例外。
    _ = (adguard_source / "Adguardhome" / "bin" / "AdGuardHome.yaml").write_text(
        (
            "user_rules:\n"
            "  - '||volces.com^$important'\n"
            "  - '@@||prod-chat-kimi.tos-cn-beijing.volces.com^$importat'\n"
        ),
        encoding="utf-8",
    )
    anti_ad_source.mkdir()
    _ = (anti_ad_source / "anti-ad-adguard.txt").write_text("@@||anti-safe.example.com^\n", encoding="utf-8")
    _ = (anti_ad_source / "anti-ad-clash.yaml").write_text(
        "payload:\n  - '+.mssdk.volces.com'\n",
        encoding="utf-8",
    )
    _ = (anti_ad_source / "anti-ad-white-for-clash.yaml").write_text(
        "payload:\n  - '+.anti-white.example.com'\n",
        encoding="utf-8",
    )
    _ = reward_source.write_text("0.0.0.0 reward.example.com\n", encoding="utf-8")
    _ = local_allow.write_text(
        (
            "@@||ark.cn-beijing.volces.com^\n"
            "@@||prod-chat-kimi.tos-cn-beijing.volces.com^\n"
        ),
        encoding="utf-8",
    )

    result = convert_repositories(
        adguard_source,
        anti_ad_source,
        reward_source,
        {
            UpstreamKind.ADGUARD_MAGISK: "adguard-sha",
            UpstreamKind.ANTI_AD: "anti-sha",
            UpstreamKind.DEAD_HORSE: "dead-horse-sha256",
            UpstreamKind.COOLAPK_1007_REWARD: "reward-sha256",
        },
        local_allow_source=local_allow,
    )
    out = tmp_path / "dist"
    write_outputs(result, out)

    # ads 仍保留整域拦截与已知广告子域, 不在转换阶段删除。
    assert "+.volces.com" in result.buckets[RuleKind.ADS].domains
    assert "+.mssdk.volces.com" in result.buckets[RuleKind.ADS].domains
    # allow 新增方舟业务域与修正后的 Kimi 例外。
    assert "+.ark.cn-beijing.volces.com" in result.buckets[RuleKind.ALLOW].domains
    assert "+.prod-chat-kimi.tos-cn-beijing.volces.com" in result.buckets[RuleKind.ALLOW].domains
    # 上游 $importat 拼写错误仍被跳过; 白名单来自 local_allow。
    assert result.stats[RuleKind.ALLOW].unsupported_modifier >= 1

    allow_txt = (out / "hyper_adrules_allow.txt").read_text(encoding="utf-8")
    ads_txt = (out / "hyper_adrules_ads.txt").read_text(encoding="utf-8")
    assert "+.ark.cn-beijing.volces.com" in allow_txt.splitlines()
    assert "+.volces.com" in ads_txt.splitlines()

