# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Data wrapper."""

from dataclasses import dataclass
from typing import Any, TypeAlias

import ldap.controls

from freeiam.ldap.attr import Attributes
from freeiam.ldap.constants import ResponseType
from freeiam.ldap.dn import DN


LDAPControlList: TypeAlias = list[ldap.controls.LDAPControl]


@dataclass
class Controls:
    """The LDAP request controls."""

    server: LDAPControlList | None = None
    client: LDAPControlList | None = None
    response: LDAPControlList | None = None

    def get(self, control):
        """Get the control from the list of response controls."""
        for ctrl in self.response or []:
            if ctrl.controlType == control.controlType:
                return ctrl
        return None

    @classmethod
    def expand(cls, controls):
        if controls is None:
            return {}
        return {'serverctrls': controls.server, 'clientctrls': controls.client}

    @classmethod
    def append_server(cls, controls, control):
        controls = Controls([]) if controls is None else controls
        controls.server.append(control)
        return controls

    @classmethod
    def set_server(cls, controls, control):
        controls = Controls([]) if controls is None else controls
        controls.server = [ctrl for ctrl in controls.server if ctrl.controlType != control.controlType] + [control]
        return controls


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
class Page:
    """A page of a paginated search result."""

    page: int
    """The current page number (starting at one)."""

    entry: int
    """The number of the current entry on this page (starting at one)."""

    page_size: int
    """The number of entries per page."""

    results: int | None = None
    """The total number of search results."""

    last_page: int | None = None
    """The last page of all search results."""

    @property
    def is_last_in_page(self) -> bool:
        """Whether this is the last entry on the current page."""
        return self.page_size == self.entry


@dataclass
class Result:
    """The wrapped result of an operation. Allows accessing response controls."""

    dn: DN
    """The new or unchanged DN of the object."""

    attr: Attributes
    """The result LDAP attributes, if the operation provides some."""

    controls: Controls | None
    """LDAP response controls."""

    _response: _Response
    """The raw LDAP result."""

    page: Page | None = None
    """The page of a paginated search result."""

    @classmethod
    def from_response(cls, dn, attr, controls, response, **kwargs):
        dn = dn if dn is None else DN.get(dn)
        attr = attr if attr is None else Attributes(attr)
        return cls(dn, attr, cls._control_response(controls, response.ctrls), response, **kwargs)

    @classmethod
    def set_controls(cls, response: _Response, controls: Controls | None):
        if controls is None:
            return
        controls.response = response.ctrls

    @classmethod
    def _control_response(cls, controls, response_ctrls):
        if controls is None:
            return Controls(None, None, response_ctrls)

        return Controls(controls.server and controls.server.copy(), controls.client and controls.client.copy(), response_ctrls)
