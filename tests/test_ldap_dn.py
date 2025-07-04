import pytest

from freeiam.errors import InvalidDN
from freeiam.ldap.constants import AVA
from freeiam.ldap.dn import DN


@pytest.fixture(scope='session')
def dn_user_container(base_dn):
    return f'cn=users,{base_dn}'


@pytest.fixture(scope='session')
def user_dn(dn_user_container):
    return DN(f'uid=Max.Mustermann,{dn_user_container}')


def test_invalid_dn():
    with pytest.raises(InvalidDN, match="Malformed DN syntax: 'foo'"):
        DN('foo')


def test_broken_samba_dn():
    assert str(DN(r'uid=foo\?bar,cn=users')) == r'uid=foo?bar,cn=users'


def test_empty_dn():
    assert str(DN('')) == ''  # noqa: PLC1901


def test_rdn(user_dn):
    assert user_dn.rdn == ('uid', 'Max.Mustermann')


def test_multi_rdn():
    assert DN('uid=1+cn=2,dc=3').multi_rdn == (('uid', '1'), ('cn', '2'))


def test_rdns(user_dn):
    assert user_dn.rdns == [
        [('uid', 'Max.Mustermann', AVA.String)],
        [('cn', 'users', AVA.String)],
        [('dc', 'freeiam', AVA.String)],
        [('dc', 'org', AVA.String)],
    ]


def test_parent(user_dn, base_dn):
    assert user_dn.parent == f'cn=users,{base_dn}'
    assert DN(base_dn).parent.parent is None


def test_get_parent(user_dn, base_dn, dn_user_container):
    assert user_dn.get_parent(dn_user_container) == dn_user_container
    assert DN(dn_user_container).get_parent(dn_user_container) is None
    assert DN(base_dn).get_parent(dn_user_container) is None


def test_endswith(user_dn, base_dn, dn_user_container):
    assert user_dn.endswith(user_dn)
    assert user_dn.endswith(dn_user_container)
    assert user_dn.endswith(base_dn)
    assert user_dn.endswith('')
    assert not user_dn.endswith(f'cn=foo,{user_dn}')
    assert not user_dn.endswith(f'cn=foo,{dn_user_container}')


def test_startswith(user_dn, base_dn, dn_user_container):
    assert user_dn.startswith(user_dn)
    assert user_dn.startswith(str(user_dn[:1]))
    assert user_dn.startswith(str(user_dn[:2]))
    assert user_dn.startswith('')
    assert not user_dn.startswith(dn_user_container)
    assert not user_dn.startswith(f'cn=foo,{user_dn}')
    assert not user_dn.startswith(f'cn=foo,{dn_user_container}')


def test_walk(user_dn, base_dn, dn_user_container):
    assert [str(x) for x in user_dn.walk(base_dn)] == [base_dn, dn_user_container, str(user_dn)]

    with pytest.raises(ValueError, match='DN does not end with given base'):
        list(user_dn.walk('cn=foo'))


def test_str(user_dn):
    assert user_dn == 'uid = Max.Mustermann , cn = users , dc = freeiam, dc = org'


def test_repr():
    assert repr(DN('foo=1,bar=2')) == '<DN foo=1,bar=2>'


def test_len(user_dn):
    assert len(user_dn) == 4  # noqa: PLR2004


def test_equal():
    assert DN('foo=1') == DN('foo=1')
    assert DN('foo=1') != DN('foo=2')
    assert DN('Foo=1') == DN('foo=1')
    assert DN('Foo=1') != DN('foo=2')
    assert DN('uid=Administrator') == DN('uid=administrator')
    assert DN('foo=Foo') != DN('foo=foo')
    assert DN('foo=1,bar=2') == DN('foo=1,bar=2')
    assert DN('bar=2,foo=1') != DN('foo=1,bar=2')
    assert DN('foo=1+bar=2') == DN('foo=1+bar=2')
    assert DN('bar=2+foo=1') == DN('foo=1+bar=2')
    assert DN('bar=2+Foo=1') == DN('foo=1+Bar=2')
    assert DN(f'foo={chr(92)}31') == DN(r'foo=1')


def test_getitem(user_dn):
    assert user_dn[1] == 'cn=users'
    assert user_dn[1:3] == 'cn=users,dc=freeiam'


def test_escape():
    assert DN.escape('+') == r'\+'
    assert DN.escape(',') == r'\,'
    assert DN.escape('=') == r'\='


def test_hash(user_dn):
    assert hash(user_dn) == hash(DN('uid = Max.Mustermann , cn = users , dc = freeiam, dc = org'))


def test_add(user_dn):
    assert str(DN('cn=foo,cn=bar') + user_dn) == 'cn=foo,cn=bar,uid=Max.Mustermann,cn=users,dc=freeiam,dc=org'


def test_normalize(user_dn):
    assert DN.normalize('uid = Max.Mustermann , cn = users , dc = freeiam, dc = org') == str(user_dn)
    assert DN.normalize(DN('uid = Max.Mustermann , cn = users , dc = freeiam, dc = org')) == str(user_dn)


def test_get(user_dn):
    assert isinstance(DN.get('uid=foo'), DN)
    assert isinstance(DN.get(DN('uid=foo')), DN)


def test_get_unique():
    assert len(DN.get_unique([
        'CN=users,dc=freeiam,dc=org',
        'cn=users,dc=freeiam,dc=org',
        'cn = users,dc=freeiam,dc=org',
        'CN=Users,dc=freeiam,dc=org',
    ])) == 1  # fmt: skip
    assert DN.get_unique_str(DN.get_unique(['cn=foo', 'cn=bar']) - DN.get_unique(['cn = foo'])) == {'cn=bar'}
