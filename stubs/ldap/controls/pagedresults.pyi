from _typeshed import Incomplete
from ldap.controls import RequestControl, ResponseControl
from pyasn1.type import univ

class PagedResultsControlValue(univ.Sequence):
    componentType: Incomplete

class SimplePagedResultsControl(RequestControl, ResponseControl):
    controlType: str
    criticality: Incomplete
    size: Incomplete
    cookie: Incomplete
    def __init__(self, criticality: bool = ..., size: int = ..., cookie: str | bytes = ...) -> None: ...
    def encodeControlValue(self) -> bytes: ...
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...
