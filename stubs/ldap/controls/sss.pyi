from _typeshed import Incomplete
from ldap.controls import RequestControl, ResponseControl
from pyasn1.type import univ

class SortKeyType(univ.Sequence):
    componentType: Incomplete

class SortKeyListType(univ.SequenceOf):
    componentType: Incomplete

class SSSRequestControl(RequestControl):
    controlType: str
    ordering_rules: Incomplete
    def __init__(self, criticality: bool = ..., ordering_rules: list[str] | str = ...) -> None: ...
    def asn1(self) -> SortKeyListType: ...
    def encodeControlValue(self) -> bytes: ...

class SortResultType(univ.Sequence):
    componentType: Incomplete

class SSSResponseControl(ResponseControl):
    controlType: str
    def __init__(self, criticality: bool = ...) -> None: ...
    sortResult: Incomplete
    attributeType: Incomplete
    result: Incomplete
    attribute_type_error: Incomplete
    def decodeControlValue(self, encoded: bytes) -> None: ...
