from __future__ import annotations

from pathlib import Path
from typing import Final

EMPTY_IPCIDR_TEXT_PLACEHOLDER: Final[str] = "# empty ipcidr ruleset\n"

# mihomo 的 ipcidr MRS 读取端要求区间数 >= 1 (cidr.ReadIpCidrSet: "length is invalid"),
# 格式上不存在可加载的空集合。空集改为编译单条 RFC 6666 discard-only 前缀中的一个地址:
# 该地址不会作为真实目的地出现, 对 allow(PASS) / 拦截(REJECT) 语义均无可观测影响。
# 仅 MRS 使用占位; text / yaml 空集 mihomo 可直接加载, 保持真实空集合。
EMPTY_IPCIDR_MRS_PLACEHOLDER_CIDR: Final[str] = "100::/128"


def ipcidr_text_has_rules(text: str) -> bool:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            return True
    return False


def write_ipcidr_mrs_source(text_path: Path, source_path: Path) -> bool:
    """写出交给 mihomo convert-ruleset 的 ipcidr text; 返回是否使用了空集占位."""
    text = text_path.read_text(encoding="utf-8") if text_path.is_file() else ""
    is_empty = not ipcidr_text_has_rules(text)
    source_path.parent.mkdir(parents=True, exist_ok=True)
    _ = source_path.write_text(f"{EMPTY_IPCIDR_MRS_PLACEHOLDER_CIDR}\n" if is_empty else text, encoding="utf-8")
    return is_empty
