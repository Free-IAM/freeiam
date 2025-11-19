import ldap.controls
from _typeshed import Incomplete
from ldap.controls import ResponseControl, ValueLessRequestControl
from pyasn1.type import univ

class SearchNoOpControl(ValueLessRequestControl, ResponseControl):
    controlType: str
    criticality: Incomplete
    def __init__(self, criticality: bool = ...) -> None: ...
    class SearchNoOpControlValue(univ.Sequence): ...
    resultCode: Incomplete
    numSearchResults: Incomplete
    numSearchContinuations: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...

class SearchNoOpMixIn(ldap.ldapobject.SimpleLDAPObject):
    def noop_search_st(self, base: str, scope: int = ..., filterstr: str = ..., timeout: int = ...) -> tuple[int, int] | tuple[None, None]: ...
