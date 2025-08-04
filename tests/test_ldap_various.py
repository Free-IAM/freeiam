import ldap as _ldap
import pytest_asyncio
from ldap.controls import RelaxRulesControl, SimplePagedResultsControl

from freeiam import errors, ldap
from freeiam.ldap._wrapper import Controls, Result  # noqa: PLC2701


def test_result_control_empty():
    ctrl = SimplePagedResultsControl()

    result = Result('', {}, Controls(None, None, []), None)
    assert result.controls.get(ctrl) is None

    result = Result('', {}, Controls(None, None, None), None)
    assert result.controls.get(ctrl) is None

    result = Result('', {}, Controls(None, None, [ctrl]), None)
    assert result.controls.get(RelaxRulesControl()) is None


def test_exception_controls():
    exc = errors.VLVError(
        _ldap.VLV_ERROR(
            {
                'msgtype': 101,
                'msgid': 5,
                'result': 76,
                'desc': 'Virtual List View error',
                'ctrls': [('2.16.840.1.113730.3.4.10', 0, b'0\x13\x02\x01\x00\x02\x01\x0b\n\x01M\x04\x08 ]\x10\x94\xad\x7f\x00\x00')],
            }
        )
    )
    ctrls = exc.controls
    assert ctrls
    assert ctrls is exc.controls


@pytest_asyncio.fixture(scope='function')
async def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn
