# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Server and Client controls."""

from ldap.controls import DecodeControlTuples, ResponseControl
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


def decode(ctrls: list[tuple[str, int, bytes]]) -> list[ResponseControl]:
    """Decode any list of supported controls."""
    return DecodeControlTuples(ctrls)


def simple_paged_results(size: int = 10, cookie: str = '', *, criticality: bool = False):
    """SimplePagedResults control."""
    return SimplePagedResultsControl(criticality, size, cookie)


def server_side_sorting(
    *ordering_rules: str | tuple[str, str | None, bool],
    criticality: bool = False,
):
    """Server Side Sorting."""
    ordering_rules_ = []
    for rule in ordering_rules:
        if not isinstance(rule, str):
            by, matchingrule, reverse = rule
            ordering_rules_.append('{}{}{}{}'.format('-' if reverse else '', by, ':' if matchingrule else '', matchingrule))
            continue
        ordering_rules_.append(rule)
    return SSSRequestControl(criticality, ordering_rules_)


def virtual_list_view(
    before_count: int = 0,
    after_count: int = 0,
    offset: int | None = None,
    content_count: int | None = None,
    greater_than_or_equal: int | None = None,
    context_id: str | None = None,
    *,
    criticality: bool = False,
):
    """Virtual List View."""
    return VLVRequestControl(criticality, before_count, after_count, offset, content_count, greater_than_or_equal, context_id)


virtual_list_view.response = VLVResponseControl


def get_effective_rights(authz_id: DN | str, *, criticality: bool = False):
    """GetEffectiveRights control."""
    authz_id = f'dn:{authz_id}' if isinstance(authz_id, DN) else authz_id
    return GetEffectiveRightsControl(criticality, authz_id.encode('UTF-8'))


def authorization_identity(*, criticality: bool = False):
    """AuthorizationIdentityRequest control."""
    return AuthorizationIdentityRequestControl(criticality)


authorization_identity.response = AuthorizationIdentityResponseControl


def dereference(deref_specs, *, criticality: bool = False):
    """Dereference control."""
    return DereferenceControl(criticality, deref_specs)


def assertion(filter_expr: str, *, criticality: bool = False):
    """Get Assertion control."""
    return AssertionControl(criticality, filter_expr)


def matched_values(filter_expr: str, *, criticality: bool = False):
    """MatchedValues control."""
    return MatchedValuesControl(criticality, filter_expr)


def persistent_search(change_types: list[LDAPChangeType], changes_only, return_entry_change_control, *, criticality: bool = False):
    """PersistentSearch control."""
    return PersistentSearchControl(criticality, change_types, changes_only, return_entry_change_control)


persistent_search.response = EntryChangeNotificationControl


def pre_read(attrs: list[str], *, criticality: bool = False):
    """PreRead control."""
    return PreReadControl(criticality, attrs)


def post_read(attrs, *, criticality: bool = False):
    """PostRead control."""
    return PostReadControl(criticality, attrs)


def session_tracking(source_ip, source_name, format_oid, tracking_identifier):
    """SessionTracking control."""
    return SessionTrackingControl(source_ip, source_name, format_oid, tracking_identifier)


def manage_dsa_information_tree(*, criticality: bool = False):
    """ManageDSAIT control."""
    return ManageDSAITControl(criticality)


def relax_rules(*, criticality: bool = False):
    """RelaxRules control."""
    return RelaxRulesControl(criticality)


def proxy_authorization(authz_id: str | DN, *, criticality: bool = False):
    """ProxyAuthz control."""
    authz_id = f'dn:{authz_id}' if isinstance(authz_id, DN) else authz_id
    return ProxyAuthzControl(criticality, authz_id.encode('UTF-8'))
