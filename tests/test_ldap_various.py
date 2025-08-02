import pytest_asyncio
from ldap.controls import RelaxRulesControl, SimplePagedResultsControl

from freeiam import ldap
from freeiam.ldap._wrapper import Controls, Result  # noqa: PLC2701


def test_result_control_empty():
    ctrl = SimplePagedResultsControl()

    result = Result('', {}, Controls(None, None, []), None)
    assert result.controls.get(ctrl) is None

    result = Result('', {}, Controls(None, None, None), None)
    assert result.controls.get(ctrl) is None

    result = Result('', {}, Controls(None, None, [ctrl]), None)
    assert result.controls.get(RelaxRulesControl()) is None


@pytest_asyncio.fixture(scope='function')
async def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn
