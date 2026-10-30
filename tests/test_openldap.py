# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
Experimental tests for OpenLDAP behavior.

Currently integration tests for RFC 4515 whitespace filters.
"""

import pytest

from freeiam import ldap
from freeiam.ldap.constants import Scope


FOO = frozenset({
    'foo',
    'foo-leading1',
    'foo-leading2',
    'foo-trailing1',
    'foo-trailing2',
    'foo-both1',
    'foo-both2',
})
SPACES = frozenset({'space1', 'space2'})
ALL = FOO | SPACES | {'foo-inner', 'bar'}


@pytest.fixture
def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    with ldap.connection.SynchronousConnection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn


def _search_uids(conn, base_dn, assertion: str) -> set[str]:
    """Return entry IDs independently of LDAP result ordering and DN casing."""
    subtree = f'ou=whitespace,{base_dn}'
    result = conn.search_dn(subtree, Scope.SUBTREE, f'(cn={assertion})')
    return {dn.value.lower() for dn in result}


@pytest.mark.parametrize(
    'assertion,expected',
    [
        (' ', SPACES),
        ('  ', SPACES),
        (' foo', FOO),
        ('foo ', FOO),
        (r'\20foo', FOO),
        (r'foo\20', FOO),
    ],
)
def test_whitespace_equality_search(conn, base_dn, assertion, expected):
    assert _search_uids(conn, base_dn, assertion) == expected


@pytest.mark.parametrize(
    'assertion,equivalent',
    [
        (' *', r'\20*'),
        ('* ', r'*\20'),
        ('  *', r'\20\20*'),
        ('*  ', r'*\20\20'),
    ],
)
def test_whitespace_substring_search(conn, base_dn, assertion, equivalent):
    """check that literal whitespace and RFC 4515 hex escaping behave identically"""
    assert _search_uids(conn, base_dn, assertion) == _search_uids(conn, base_dn, equivalent)


def test_whitespace_presence_search(conn, base_dn):
    assert _search_uids(conn, base_dn, '*') == ALL


def test_whitespace_substring_is_not_equality(conn, base_dn):
    # wildcard can match values which a complete equality assertion cannot
    assert _search_uids(conn, base_dn, '*foo*') >= FOO
    assert _search_uids(conn, base_dn, 'foo') == FOO
