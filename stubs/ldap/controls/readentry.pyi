from _typeshed import Incomplete
from ldap._types import LDAPEntryDict
from ldap.controls import LDAPControl

class ReadEntryControl(LDAPControl):
    criticality: Incomplete
    attrList: Incomplete
    entry: LDAPEntryDict | None

    def __init__(self, criticality: bool = False, attrList: list[str] | None = None) -> None: ...
    def encodeControlValue(self) -> bytes: ...
    dn: Incomplete

    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...

class PreReadControl(ReadEntryControl):
    controlType: Incomplete

class PostReadControl(ReadEntryControl):
    controlType: Incomplete
