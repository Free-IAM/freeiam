import io

import pytest

from freeiam.ldap._wrapper import Result  # noqa: PLC2701
from freeiam.ldap.attr import Attributes
from freeiam.ldap.dn import DN


@pytest.fixture
def result():
    return Result(
        DN('uid=test,dc=example,dc=org'),
        Attributes({
            'cn': [b'Test User'],
            'mail': [b'test@example.org'],
        }),
        None,
        None,
    )


def test_ldif(result):
    assert result.ldif() == ('dn: uid=test,dc=example,dc=org\ncn: Test User\nmail: test@example.org\n\n')


def test_write_ldif(result):
    fd = io.StringIO()

    result.write_ldif(fd)
    assert fd.getvalue() == result.ldif()


def test_write_ldif_multiple_results(result):
    fd = io.StringIO()

    result.write_ldif(fd)
    result.write_ldif(fd)

    assert fd.getvalue() == result.ldif() * 2


def test_pprint(result, capsys):
    assert result.pprint() is None
    assert capsys.readouterr().out == result.ldif()


def test_pprint_fd(result):
    fd = io.StringIO()

    assert result.pprint(fd) is None
    assert fd.getvalue() == result.ldif()


def test_ldif_without_dn():
    result = Result(None, None, None, None)
    assert result.ldif() == 'dn: \n\n'


def test_ldif_without_attributes():
    result = Result(DN('uid=test,dc=example,dc=org'), None, None, None)
    assert result.ldif() == 'dn: uid=test,dc=example,dc=org\n\n'
