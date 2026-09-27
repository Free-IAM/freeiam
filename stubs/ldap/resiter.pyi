from collections.abc import Iterator
from typing import Any

from ldap.controls import ResponseControl
from ldap.ldapobject import LDAPObject as _Base

class ResultProcessor(_Base):
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def allresults(
        self, msgid: int, timeout: int = -1, add_ctrls: int = 0
    ) -> Iterator[tuple[int | None, Any | None, int | None, list[ResponseControl] | None]]: ...
