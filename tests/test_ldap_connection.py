import contextlib
import logging

import pytest
import pytest_asyncio

from freeiam import errors, ldap


log = logging.getLogger(__name__)


TESTUSERNAME = 'testuser'
PAGEPREFIX = 'page'
TESTUSERNAME_B = TESTUSERNAME.encode()


@pytest_asyncio.fixture(scope='function')
async def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn


@pytest.fixture(scope='session')
def sess_conn(ldap_server, base_dn):
    """
    A session scoped fixture which should only be used by other fixtures.

    Use it to make initial setup as it can loose its connection and become stale.
    """
    with ldap.connection.SynchronousConnection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn


def create_ou(conn, dn):
    name = ldap.DN.get(dn).rdn[1]
    with contextlib.suppress(errors.AlreadyExists):
        conn.add(dn, {'objectClass': [b'top', b'organizationalUnit'], 'ou': [name.encode()]})


def create_user(conn, dn, **kw):
    name = ldap.DN.get(dn).rdn[1]
    attrs = {
        'objectClass': [b'inetOrgPerson'],
        'uid': [name.encode()],
        'cn': [name.encode()],
        'sn': [name.encode()],
        'mail': [f'{name}@freeiam.org'.encode()],
    }
    attrs.update({k: [v.encode()] for k, v in kw.items()})
    with contextlib.suppress(errors.AlreadyExists):
        conn.add(dn, attrs)
    return dn, attrs


@pytest.fixture(scope='session')
def testuser(sess_conn, base_dn):
    """A testuser which exist the whole session"""
    return create_user(sess_conn, f'cn={TESTUSERNAME},{base_dn}', sn='User')


@pytest.fixture
def testuser2(sess_conn, base_dn):
    """A testuser which can be destroyed"""
    dn, _attrs = create_user(sess_conn, f'cn={TESTUSERNAME}2,{base_dn}', sn='User')
    yield dn
    with contextlib.suppress(errors.NoSuchObject):
        sess_conn.delete(dn)


@pytest.fixture(scope='session')
def ou_structure(sess_conn, base_dn):
    dn = ldap.DN(f'cn={TESTUSERNAME}3,ou=Newsletter,ou=Marketing,ou=Departments,{base_dn}')
    dn2 = ldap.DN(f'cn={TESTUSERNAME}4,ou=Sales,ou=Departments,{base_dn}')
    base = dn.parent.parent.parent
    create_ou(sess_conn, base)
    create_ou(sess_conn, dn.parent.parent)
    create_ou(sess_conn, dn.parent)
    create_ou(sess_conn, dn2.parent)
    create_user(sess_conn, dn)
    create_user(sess_conn, dn2)
    return base


@pytest.mark.asyncio
async def test_compare_dn(conn, testuser, testuser2, ou_structure):
    dn = testuser[0]
    changed_case = TESTUSERNAME.replace('t', 'T').replace('u', 'U').replace('s', 'S')
    assert await conn.compare_dn('', '')
    assert await conn.compare_dn(dn, f'cn={changed_case} , dc = FreeIAM , dc=Org')
    assert not await conn.compare_dn(dn, 'cn=notexists,dc=FreeIAM,dc=Org')
    assert not await conn.compare_dn(dn, testuser2)
    assert not await conn.compare_dn(testuser2, dn)
    with pytest.raises(errors.NoSuchObject, match=r'No such object \(exists: dc=freeiam,dc=org\) \(base: cn=notexists,dc=FreeIAM,dc=Org\)'):
        assert not await conn.compare_dn('cn=notexists,dc=FreeIAM,dc=Org', dn)
    assert await conn.compare_dn(f'ou=Marketing,{ou_structure}', f'ou=Marketing,{ou_structure}')
    assert not await conn.compare_dn(f'ou=Sales,{ou_structure}', f'ou=Marketing,{ou_structure}')
