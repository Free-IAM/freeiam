from _typeshed import Incomplete
from ldap.controls.libldap import *
from ldap.controls.simple import *

KNOWN_RESPONSE_CONTROLS: dict[str, type[ResponseControl]]

class RequestControl:
    controlType: Incomplete
    criticality: Incomplete
    encodedControlValue: Incomplete
    def __init__(self, controlType: str | None = ..., criticality: bool = ..., encodedControlValue: bytes | None = ...) -> None: ...
    def encodeControlValue(self) -> bytes | None: ...

class ResponseControl:
    controlType: Incomplete
    criticality: Incomplete
    def __init__(self, controlType: str | None = ..., criticality: bool = ...) -> None: ...
    encodedControlValue: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...

class LDAPControl(RequestControl, ResponseControl):
    controlType: Incomplete
    criticality: Incomplete
    controlValue: Incomplete
    encodedControlValue: Incomplete
    def __init__(
        self, controlType: str | None = ..., criticality: bool = ..., controlValue: str | None = ..., encodedControlValue: bytes | None = ...
    ) -> None: ...

def RequestControlTuples(ldapControls: list[RequestControl] | None) -> list[tuple[str | None, bool, bytes | None]] | None: ...
def DecodeControlTuples(
    ldapControlTuples: list[tuple[str, bool, bytes]] | None, knownLDAPControls: dict[str, type[ResponseControl]] | None = ...
) -> list[ResponseControl]: ...

# Names in __all__ with no definition:
#   AssertionControl
#   BooleanControl
#   ManageDSAITControl
#   MatchedValuesControl
#   RelaxRulesControl
#   SimplePagedResultsControl
#   ValueLessRequestControl
