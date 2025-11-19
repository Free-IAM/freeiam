from _typeshed import Incomplete
from ldap.controls import LDAPControl
from pyasn1.type import univ
from pyasn1_modules.rfc2251 import AttributeDescriptionList

DEREF_CONTROL_OID: str
AttributeList = AttributeDescriptionList

class DerefSpec(univ.Sequence):
    componentType: Incomplete

class DerefSpecs(univ.SequenceOf):
    componentType: Incomplete

class AttributeValues(univ.SetOf):
    componentType: Incomplete

class PartialAttribute(univ.Sequence):
    componentType: Incomplete

class PartialAttributeList(univ.SequenceOf):
    componentType: Incomplete
    tagSet: Incomplete

class DerefRes(univ.Sequence):
    componentType: Incomplete

class DerefResultControlValue(univ.SequenceOf):
    componentType: Incomplete

class DereferenceControl(LDAPControl):
    controlType: Incomplete
    derefSpecs: Incomplete
    def __init__(self, criticality: bool = ..., derefSpecs: dict[str, list[str]] | None = ...) -> None: ...
    def encodeControlValue(self) -> bytes: ...
    derefRes: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...
