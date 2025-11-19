from _typeshed import Incomplete
from ldap.controls import ResponseControl, ValueLessRequestControl
from pyasn1.type import univ

class PasswordPolicyWarning(univ.Choice):
    componentType: Incomplete

class PasswordPolicyError(univ.Enumerated):
    namedValues: Incomplete
    subtypeSpec: Incomplete

class PasswordPolicyResponseValue(univ.Sequence):
    componentType: Incomplete

class PasswordPolicyControl(ValueLessRequestControl, ResponseControl):
    controlType: str
    criticality: Incomplete
    timeBeforeExpiration: Incomplete
    graceAuthNsRemaining: Incomplete
    error: Incomplete
    def __init__(self, criticality: bool = ...) -> None: ...
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...
