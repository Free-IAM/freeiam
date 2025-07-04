# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Data wrapper."""

from dataclasses import dataclass
from typing import Any

from freeiam.ldap.attr import Attributes
from freeiam.ldap.constants import ResponseType
from freeiam.ldap.dn import DN


@dataclass
class _Response:
    """The raw response of ldapobject.result4()."""

    type: ResponseType | None
    data: list | None
    msgid: int | None
    ctrls: list[Any] | None
    name: Any
    value: Any

    def __post_init__(self):
        if not isinstance(self.type, ResponseType | None):
            self.type = ResponseType(self.type)


@dataclass
class Result:
    """The wrapped result of an operation. Allows accessing response controls."""

    dn: DN
    """The new or unchanged DN of the object."""

    attr: Attributes
    """The result LDAP attributes, if the operation provides some."""

    controls: Any | None
    """LDAP response controls."""

    _response: _Response
    """The raw LDAP result."""

    def get_control(self, control):
        """Get the control from the list of response controls."""
        for ctrl in self.controls:
            if ctrl.controlType == control.controlType:
                return ctrl
        return None
