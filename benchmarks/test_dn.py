# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Benchmarks for LDAP distinguished name operations."""

import pytest

from freeiam.ldap import dn as dn_module
from freeiam.ldap.dn import DN


DN_CASES = {
    'user': 'uid=Max.Mustermann,cn=users,dc=freeiam,dc=org',
    'multi_rdn': r'uid=Max\20Mustermann+cn=Max\20Mustermann,ou=People,dc=freeiam,dc=org',
    'escaped': r'cn=Lu\C4\8Di\C4\87,ou=People,dc=freeiam,dc=org',
    'complex': r'uid=admin+cn=Directory\, Administrator,ou=Security,ou=People,dc=freeiam,dc=org',
}


@pytest.mark.parametrize('case, expression', DN_CASES.items(), ids=DN_CASES)
def test_dn_parse_cold(benchmark, case, expression):
    """Benchmark DN parsing when the native parser cache is cold."""
    benchmark.pedantic(
        lambda: DN(expression),
        setup=dn_module._to_dn.cache_clear,
        rounds=100,
        iterations=1,
    )


@pytest.mark.parametrize('case, expression', DN_CASES.items(), ids=DN_CASES)
def test_dn_parse_cached(benchmark, case, expression):
    """Benchmark normal repeated DN construction with the parser cache warm."""
    DN(expression)
    benchmark(lambda: DN(expression))


@pytest.mark.parametrize('case, expression', DN_CASES.items(), ids=DN_CASES)
def test_dn_normalize(benchmark, case, expression):
    """Benchmark normalization of typical LDAP distinguished names."""
    benchmark(lambda: DN.normalize(expression))


def test_dn_equality(benchmark):
    """Benchmark normalized DN equality, including multi-valued RDNs."""
    left = DN(r'CN=Admin+UID=42,OU=People,DC=freeiam,DC=org')
    right = DN(r'uid=42+cn=admin,ou=people,dc=freeiam,dc=org')
    benchmark(lambda: left == right)


def test_dn_compose(benchmark):
    """Benchmark composing a user DN from relative and base components."""
    base = DN('dc=freeiam,dc=org')
    benchmark(lambda: DN.compose(('uid', 'Max.Mustermann'), 'cn=users', base))
