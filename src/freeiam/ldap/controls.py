# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Server and Client controls."""

from ldap.controls import SimplePagedResultsControl


__all__ = ('simple_paged_results',)


def simple_paged_results(*args, **kwargs):
    """SimplePagedResults control."""
    return SimplePagedResultsControl(*args, **kwargs)
