import pytest_asyncio
from ldap.controls import RelaxRulesControl, SimplePagedResultsControl

from freeiam import ldap
from freeiam.ldap._wrapper import Result  # noqa: PLC2701


def test_result_control_empty():
    result = Result('', {}, [], None)
    ctrl = SimplePagedResultsControl()
    assert result.get_control(ctrl) is None

    result = Result('', {}, [ctrl], None)
    assert result.get_control(RelaxRulesControl()) is None


@pytest_asyncio.fixture(scope='function')
async def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn
