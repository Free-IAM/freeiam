# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Server and Client controls."""

from collections.abc import Callable
from typing import Any, Protocol, TypeVar, cast

from ldap.controls import DecodeControlTuples, RequestControl, ResponseControl
from ldap.controls.deref import DereferenceControl
from ldap.controls.libldap import AssertionControl, MatchedValuesControl
from ldap.controls.pagedresults import SimplePagedResultsControl

# from ldap.controls.openldap import SearchNoOpControl
# from ldap.controls.ppolicy import PasswordPolicyControl
from ldap.controls.psearch import EntryChangeNotificationControl, PersistentSearchControl

# from ldap.controls.pwdpolicy import PasswordExpiringControl
# from ldap.controls.pwdpolicy import PasswordExpiredControl
from ldap.controls.readentry import PostReadControl, PreReadControl
from ldap.controls.sessiontrack import SessionTrackingControl
from ldap.controls.simple import (
    AuthorizationIdentityRequestControl,
    AuthorizationIdentityResponseControl,
    GetEffectiveRightsControl,
    ManageDSAITControl,
    ProxyAuthzControl,
    RelaxRulesControl,
)

# from ldap.controls.libldap import SimplePagedResultsControl
from ldap.controls.sss import SSSRequestControl
from ldap.controls.vlv import VLVRequestControl, VLVResponseControl

from freeiam.ldap._wrapper import Controls
from freeiam.ldap.constants import LDAPChangeType
from freeiam.ldap.dn import DN


__all__ = (
    'Controls',
    'assertion',
    'authorization_identity',
    'decode',
    'dereference',
    'get_effective_rights',
    'manage_dsa_information_tree',
    'matched_values',
    'persistent_search',
    'post_read',
    'pre_read',
    'proxy_authorization',
    'relax_rules',
    'server_side_sorting',
    'session_tracking',
    'simple_paged_results',
    'virtual_list_view',
)


class RequestControlType(Protocol):
    response: type[ResponseControl]

    def __call__(self, *args: Any, **kwargs: Any) -> RequestControl: ...  # pragma: no cover


F = TypeVar('F', bound=Callable[..., RequestControl])


def _control(fn: F) -> RequestControlType:
    return cast('RequestControlType', fn)


def decode(ctrls: list[tuple[str, bool, bytes]]) -> list[ResponseControl]:
    """Decode any list of supported controls."""
    return DecodeControlTuples(ctrls)


def simple_paged_results(size: int = 10, cookie: str = '', *, criticality: bool = False) -> SimplePagedResultsControl:
    """SimplePagedResults control."""
    return SimplePagedResultsControl(criticality, size, cookie)


def server_side_sorting(
    *ordering_rules: str | tuple[str, str | None, bool],
    criticality: bool = False,
) -> SSSRequestControl:
    """Server Side Sorting."""
    ordering_rules_ = []
    for rule in ordering_rules:
        if not isinstance(rule, str):
            by, matchingrule, reverse = rule
            ordering_rules_.append('{}{}{}{}'.format('-' if reverse else '', by, ':' if matchingrule else '', matchingrule))
            continue
        ordering_rules_.append(rule)
    return SSSRequestControl(criticality, ordering_rules_)


@_control
def virtual_list_view(
    before_count: int = 0,
    after_count: int = 0,
    offset: int | None = None,
    content_count: int | None = None,
    greater_than_or_equal: str | None = None,
    context_id: str | None = None,
    *,
    criticality: bool = False,
) -> VLVRequestControl:
    """Virtual List View."""
    return VLVRequestControl(criticality, before_count, after_count, offset, content_count, greater_than_or_equal, context_id)


virtual_list_view.response = VLVResponseControl


def get_effective_rights(authz_id: DN | str, *, criticality: bool = False) -> GetEffectiveRightsControl:
    """GetEffectiveRights control."""
    authz_id = f'dn:{authz_id}' if isinstance(authz_id, DN) else authz_id
    return GetEffectiveRightsControl(criticality, authz_id.encode('UTF-8'))


@_control
def authorization_identity(*, criticality: bool = False) -> AuthorizationIdentityRequestControl:
    """AuthorizationIdentityRequest control."""
    return AuthorizationIdentityRequestControl(criticality)


authorization_identity.response = AuthorizationIdentityResponseControl


def dereference(deref_specs: dict[str, list[str]], *, criticality: bool = False) -> DereferenceControl:
    """Dereference control."""
    return DereferenceControl(criticality, deref_specs)


def assertion(filter_expr: str, *, criticality: bool = False) -> AssertionControl:
    """Get Assertion control."""
    return AssertionControl(criticality, filter_expr)


def matched_values(filter_expr: str, *, criticality: bool = False) -> MatchedValuesControl:
    """MatchedValues control."""
    return MatchedValuesControl(criticality, filter_expr)


@_control
def persistent_search(
    change_types: list[LDAPChangeType], changes_only: bool, return_entry_change_control: bool, *, criticality: bool = False
) -> PersistentSearchControl:
    """PersistentSearch control."""
    return PersistentSearchControl(criticality, cast('list[int]', change_types), changes_only, return_entry_change_control)


persistent_search.response = EntryChangeNotificationControl


def pre_read(attrs: list[str], *, criticality: bool = False) -> PreReadControl:
    """PreRead control."""
    return PreReadControl(criticality, attrs)


def post_read(attrs: list[str], *, criticality: bool = False) -> PostReadControl:
    """PostRead control."""
    return PostReadControl(criticality, attrs)


def session_tracking(source_ip: str, source_name: str, format_oid: str, tracking_identifier: str) -> SessionTrackingControl:
    """SessionTracking control."""
    return SessionTrackingControl(source_ip, source_name, format_oid, tracking_identifier)


def manage_dsa_information_tree(*, criticality: bool = False) -> ManageDSAITControl:
    """ManageDSAIT control."""
    return ManageDSAITControl(criticality)


def relax_rules(*, criticality: bool = False) -> RelaxRulesControl:
    """RelaxRules control."""
    return RelaxRulesControl(criticality)


def proxy_authorization(authz_id: str | DN, *, criticality: bool = False) -> ProxyAuthzControl:
    """ProxyAuthz control."""
    authz_id = f'dn:{authz_id}' if isinstance(authz_id, DN) else authz_id
    return ProxyAuthzControl(criticality, authz_id.encode('UTF-8'))


def transaction(transaction_id: bytes | None = None, *, criticality: bool = True) -> 'TransactionSpecificationControl':
    """TransactionSpecification control."""
    return TransactionSpecificationControl(criticality, transaction_id)


class TransactionSpecificationControl(RequestControl):
    controlType = '1.3.6.1.1.21.2'  # noqa: N815

    def __init__(self, criticality: bool = True, txn_id: bytes | None = None):
        super().__init__(self.controlType, criticality, txn_id or b'')
