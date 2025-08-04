# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Server and Client controls."""

from ldap.controls import DecodeControlTuples, ResponseControl
from ldap.controls.pagedresults import SimplePagedResultsControl
from ldap.controls.sss import SSSRequestControl
from ldap.controls.vlv import VLVRequestControl


__all__ = ('simple_paged_results',)


def decode(ctrls: list[tuple[str, int, bytes]]) -> list[ResponseControl]:
    return DecodeControlTuples(ctrls)


def simple_paged_results(size=10, cookie='', *, criticality=False):
    """SimplePagedResults control."""
    return SimplePagedResultsControl(criticality, size, cookie)


def server_side_sorting(
    *ordering_rules: str | tuple[str, str | None, bool],
    criticality=False,
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
    before_count=0,
    after_count=0,
    offset=None,
    content_count=None,
    greater_than_or_equal=None,
    context_id=None,
    *,
    criticality=False,
):
    """Virtual List View."""
    return VLVRequestControl(criticality, before_count, after_count, offset, content_count, greater_than_or_equal, context_id)
