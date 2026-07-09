from typing import TypeAlias

from _typeshed import Incomplete

LDAPTokenDictValue: TypeAlias = tuple[str, ...]
LDAPTokenDict: TypeAlias = dict[str, LDAPTokenDictValue]
TOKENS_FINDALL: Incomplete
UNESCAPE_PATTERN: Incomplete

def split_tokens(s: str) -> list[str]: ...
def parse_tokens(tokens: list[str], known_tokens: list[str]) -> tuple[str, LDAPTokenDict]: ...
