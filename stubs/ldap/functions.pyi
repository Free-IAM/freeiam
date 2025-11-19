from collections.abc import Callable
from typing import Any, BinaryIO, TextIO

from ldap.dn import explode_dn as explode_dn, explode_rdn as explode_rdn
from ldap.ldapobject import LDAPObject

def initialize(
    uri: str | None,
    trace_level: int = ...,
    trace_file: TextIO = ...,
    trace_stack_limit: int = ...,
    bytes_mode: Any | None = ...,
    fileno: int | BinaryIO | None = ...,
    **kwargs: Any,
) -> LDAPObject: ...
def get_option(option: int) -> Any: ...
def set_option(option: int, invalue: Any) -> int: ...
def escape_str(escape_func: Callable[[str], str], s: str, *args: str) -> str: ...
def strf_secs(secs: float) -> str: ...
def strp_secs(dt_str: str) -> int: ...

# Names in __all__ with no definition:
#   init
#   open
