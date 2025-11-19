from _typeshed import Incomplete
from ldap.controls import KNOWN_RESPONSE_CONTROLS as KNOWN_RESPONSE_CONTROLS, LDAPControl as LDAPControl
from ldap.types import LDAPEntryDict as LDAPEntryDict

class ReadEntryControl(LDAPControl):
    criticality: Incomplete
    attrList: Incomplete
    entry: Incomplete
    def __init__(self, criticality: bool = ..., attrList: list[str] | None = ...) -> None: ...
    def encodeControlValue(self) -> bytes: ...
    dn: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...

class PreReadControl(ReadEntryControl):
    controlType: Incomplete

class PostReadControl(ReadEntryControl):
    controlType: Incomplete
