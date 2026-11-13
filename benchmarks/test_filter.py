# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Benchmarks for the LDAP filter parser backends."""

import pytest

from freeiam.ldap.filter import Filter


FILTER_CASES = {
    'equality': '(cn=John Doe)',
    'presence': '(objectClass=*)',
    'substring': '(mail=*+engineering@freeiam.org)',
    'escaped': r'(description=contains\28parentheses\29\2a)',
    'extensible': '(cn:dn:caseIgnoreMatch:=John Doe)',
    'nested': '(&(objectClass=inetOrgPerson)(|(uid=jdoe)(mail=john.doe@freeiam.org))(!(accountStatus=disabled)))',
    'complex': (
        '(&(|(cn=John Doe)(sn=*)(givenName=Jo*n*Do*)(uid>=1000)(uid<=2000)(mail~=j.doe@freeiam.org)'
        '(!(objectClass=inetOrgPerson)))(description=contains\\28parentheses,spaces\\20\\29\\5cand\\2astars\\2a)'
        '(objectClass:caseIgnoreMatch:=inetOrgPerson)(cn:dn:2.4.6.8.10:=John\\20Doe))'
    ),
}


@pytest.mark.parametrize('parser', ['lark', 'libldap'])
@pytest.mark.parametrize('case, expression', FILTER_CASES.items(), ids=FILTER_CASES)
def test_filter_parse(benchmark, parser, case, expression):
    """Benchmark parsing equivalent filter expressions with each backend."""
    benchmark(lambda: Filter(expression, parser=parser))
