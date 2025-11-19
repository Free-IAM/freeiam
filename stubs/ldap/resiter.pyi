from collections.abc import Iterator
from typing import Any

import ldap
from ldap.controls import ResponseControl as ResponseControl

class ResultProcessor(ldap.ldapobject.LDAPObject):
    def allresults(
        self, msgid: int, timeout: int = ..., add_ctrls: int = ...
    ) -> Iterator[tuple[int | None, Any | None, int | None, list[ResponseControl] | None]]: ...
