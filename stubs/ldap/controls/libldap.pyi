from _typeshed import Incomplete
from ldap.controls import LDAPControl, RequestControl

class AssertionControl(RequestControl):
    controlType: Incomplete
    criticality: Incomplete
    filterstr: Incomplete

    def __init__(self, criticality: bool = True, filterstr: str = '(objectClass=*)') -> None: ...
    def encodeControlValue(self) -> bytes: ...

class MatchedValuesControl(RequestControl):
    controlType: Incomplete
    criticality: Incomplete
    filterstr: Incomplete

    def __init__(self, criticality: bool = False, filterstr: str = '(objectClass=*)') -> None: ...
    def encodeControlValue(self) -> bytes: ...

class SimplePagedResultsControl(LDAPControl):
    controlType: Incomplete
    criticality: Incomplete

    def __init__(self, criticality: bool = False, size: int | None = None, cookie: str | bytes | None = None) -> None: ...
    def encodeControlValue(self) -> bytes: ...
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...
