from _typeshed import Incomplete
from ldap.controls import RequestControl, ResponseControl
from pyasn1.type import univ

CHANGE_TYPES_INT: Incomplete
CHANGE_TYPES_STR: Incomplete

class PersistentSearchControl(RequestControl):
    class PersistentSearchControlValue(univ.Sequence):
        componentType: Incomplete

    controlType: str
    changeTypes: Incomplete
    def __init__(self, criticality: bool = ..., changeTypes: list[int] | None = ..., changesOnly: bool = ..., returnECs: bool = ...) -> None: ...
    def encodeControlValue(self) -> bytes: ...

class ChangeType(univ.Enumerated):
    namedValues: Incomplete
    subtypeSpec: Incomplete

class EntryChangeNotificationValue(univ.Sequence):
    componentType: Incomplete

class EntryChangeNotificationControl(ResponseControl):
    controlType: str
    changeType: Incomplete
    previousDN: Incomplete
    changeNumber: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...
