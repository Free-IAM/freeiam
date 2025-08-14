import ldap as _ldap
import pytest
from ldap.controls import RelaxRulesControl, SimplePagedResultsControl

from freeiam import errors, ldap
from freeiam.ldap._wrapper import Result  # noqa: PLC2701
from freeiam.ldap.constants import LDAPChangeType, Mod, Scope
from freeiam.ldap.controls import (
    Controls,
    assertion,
    authorization_identity,
    dereference,
    get_effective_rights,
    manage_dsa_information_tree,
    matched_values,
    persistent_search,
    post_read,
    pre_read,
    proxy_authorization,
    relax_rules,
    session_tracking,
)
from freeiam.ldap.dn import DN


@pytest.fixture
def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    with ldap.connection.SynchronousConnection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn


def test_result_control_empty():
    ctrl = SimplePagedResultsControl()

    result = Result('', {}, Controls(None, None, []), None)
    assert result.controls.get(ctrl) is None

    result = Result('', {}, Controls(None, None, None), None)
    assert result.controls.get(ctrl) is None

    result = Result('', {}, Controls(None, None, [ctrl]), None)
    assert result.controls.get(RelaxRulesControl()) is None


def test_exception_controls():
    exc = errors.VLVError.from_ldap_exception(
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


def test_set_connection_server_controls(conn, base_dn):
    dn = f'cn=user02,ou=users,{base_dn}'
    ctrl = pre_read(['givenName'], criticality=True)
    conn.set_controls(Controls([ctrl]))
    try:
        result = conn.modify_ml(dn, [(Mod.Replace, 'givenName', b'Foo')])
        preread = result.controls.get(ctrl)
        assert not preread.entry.get('givenName')

        result = conn.modify_ml(dn, [(Mod.Replace, 'givenName', b'Test')])
        preread = result.controls.get(ctrl)
        assert preread.entry['givenName'][0] == b'Foo'
    finally:
        conn.set_controls(Controls([]))

    result = conn.modify_ml(dn, [(Mod.Replace, 'givenName', b'Bar')])
    assert not result.controls.get(ctrl)


def test_modify_with_assertion_control(conn, base_dn):
    dn = f'cn=user01,ou=users,{base_dn}'
    ctrl = assertion('(sn=Bar1)', criticality=True)
    conn.modify_ml(dn, [(Mod.Replace, 'sn', b'Foo1')], controls=Controls([ctrl]))

    ctrl = assertion('(sn=Bar1)', criticality=True)
    with pytest.raises(errors.AssertionFailed):
        conn.modify_ml(dn, [(Mod.Replace, 'sn', b'Foo2')], controls=Controls([ctrl]))


def test_modify_with_pre_and_postread(conn, base_dn):
    dn = f'cn=user02,ou=users,{base_dn}'
    ctrl = post_read(['sn'], criticality=True)
    ctrl2 = pre_read(['sn'], criticality=True)
    result = conn.modify_ml(dn, [(Mod.Replace, 'sn', b'Test')], controls=Controls([ctrl, ctrl2]))
    postread = result.controls.get(ctrl)
    preread = result.controls.get(ctrl2)
    assert postread.entry['sn'][0] == b'Test'
    assert preread.entry['sn'][0] == b'Bar2'


@pytest.mark.xfail(raises=errors.UnavailableCriticalExtension)
def test_get_effective_rights(conn, base_dn):
    ctrl = get_effective_rights(conn.whoami(), criticality=True)
    result = conn.get(f'cn=user02,ou=users,{base_dn}', controls=Controls([ctrl]))
    assert result.attr['entryLevelRights']
    assert result.attr['attributeLevelRights']


@pytest.mark.xfail(raises=errors.UnavailableCriticalExtension)
def test_bind_with_authzid_control(conn, base_dn):
    ctrl = authorization_identity(criticality=True)
    result = conn.bind(f'uid=testuser,ou=users,{base_dn}', 'secret', controls=Controls([ctrl]))
    res = result.controls.get(authorization_identity.response)
    dn = res.authzId.decode('UTF-8')
    assert dn.startswith('dn:')
    assert DN(dn.removeprefix('dn:')) == conn.whoami()


@pytest.mark.xfail(raises=errors.UnavailableCriticalExtension)
def test_dereference_control_not_supported(conn, base_dn):
    ctrl = dereference({'member': 'cn'}, criticality=True)
    conn.search(f'ou=groups,{base_dn}', Scope.Subtree, '(objectClass=groupOfNames)', controls=Controls([ctrl]))


def test_matched_values_control(conn, base_dn):
    ctrl = matched_values('(sn=*)', criticality=True)
    results = conn.search(f'ou=users,{base_dn}', Scope.Subtree, '(objectClass=inetOrgPerson)', controls=Controls([ctrl]))
    assert results
    assert all(tuple(res.attr.keys()) == ('sn',) for res in results)


@pytest.mark.xfail(raises=errors.UnavailableCriticalExtension)
@pytest.mark.timeout(10)
def test_persistent_search_control(conn, base_dn):
    ctrl = persistent_search([LDAPChangeType.Modify], changes_only=True, return_entry_change_control=True, criticality=True)
    # this will block until any change is done
    # TODO: modify in a thread
    conn.search(f'ou=users,{base_dn}', Scope.Subtree, '(objectClass=inetOrgPerson)', controls=Controls([ctrl]))


def test_session_tracking_control(conn, base_dn):
    ctrl = session_tracking('127.0.0.1', 'test-client', '1.3.6.1.4.1.1466.115.121.1.15', 'traceid')
    conn.search(base_dn, Scope.Base, '(objectClass=*)', controls=Controls([ctrl]))


def test_manage_dsa_it_control(conn, base_dn):
    ctrl = manage_dsa_information_tree(criticality=True)
    res = conn.search(f'{base_dn}', Scope.Base, '(objectClass=*)', controls=Controls([ctrl]))
    assert isinstance(res, list)


def test_relax_rules_control(conn, base_dn):
    ctrl = relax_rules(criticality=True)
    conn.modify_ml(f'cn=user01,ou=users,{base_dn}', [(Mod.Replace, 'entryUUID', b'00000000-0000-0000-0000-000000000000')], controls=Controls([ctrl]))
    assert conn.get_attr(f'cn=user01,ou=users,{base_dn}', 'entryUUID') == [b'00000000-0000-0000-0000-000000000000']


def test_proxy_authz_control(conn, base_dn):
    ctrl = proxy_authorization(DN(f'cn=admin,{base_dn}'), criticality=True)
    res = conn.search(f'{base_dn}', Scope.Base, '(objectClass=*)', controls=Controls([ctrl]))
    assert isinstance(res, list)
