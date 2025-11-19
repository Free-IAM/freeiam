from _typeshed import Incomplete
from ldap.controls import ResponseControl

class PasswordExpiringControl(ResponseControl):
    controlType: str
    gracePeriod: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...

class PasswordExpiredControl(ResponseControl):
    controlType: str
    passwordExpired: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...
