import threading
from typing import Any

from _ldap import *
from _typeshed import Incomplete
from ldap.dn import dn2str as dn2str, explode_dn as explode_dn, explode_rdn as explode_rdn, str2dn as str2dn
from ldap.functions import (
    escape_str as escape_str,
    get_option as get_option,
    initialize as initialize,
    set_option as set_option,
    strf_secs as strf_secs,
    strp_secs as strp_secs,
)
from ldap.ldapobject import NO_UNIQUE_ENTRY as NO_UNIQUE_ENTRY, LDAPBytesWarning as LDAPBytesWarning

LIBLDAP_API_INFO: Incomplete
OPT_NAMES_DICT: Incomplete

class DummyLock:
    def __init__(self) -> None: ...
    def acquire(self) -> bool: ...
    def release(self) -> None: ...

LDAPLockBaseClass: type[DummyLock | threading.Lock]
LDAPLockBaseClass = threading.Lock

class LDAPLock:
    def __init__(self, lock_class: type[Any] | None = ..., desc: str = ...) -> None: ...
    def acquire(self) -> bool: ...
    def release(self) -> None: ...

OPT_DIAGNOSTIC_MESSAGE = OPT_ERROR_STRING
