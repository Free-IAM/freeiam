from freeiam import errors
from freeiam.ldap.constants import LDAPChangeType, Mod, Scope


base_dn = 'dc=freeiam,dc=org'


def decode(self, values, encoding='UTF-8'):
    return values[0].decode(encoding)


async def example_ldap_post_read_controls(conn):
    # use PostRead Control
    from freeiam.ldap.controls import Controls, post_read

    post_read_control = post_read(
        [
            '*',  # every regular attribute
            '+',  # every operational attribute (metadata)
        ],
        criticality=True,
    )
    controls = Controls([post_read_control])

    # receive e.g. the entryUUID directly after creations
    dn = f'uid=max.mustermann,{base_dn}'
    attrs = {
        'objectClass': [b'inetOrgPerson'],
        'uid': [b'max.mustermann'],
        'cn': [b'Max Mustermann'],
        'givenName': [b'Max'],
        'sn': [b'Mustermann'],
        'mail': [b'max.mustermann@freeiam.org'],
    }
    result = await conn.add(dn, attrs, controls=controls)
    print(result.dn, result.attrs)

    entry = result.controls.get(post_read_control).entry
    print(decode(entry['entryUUID']))
    print(decode(entry['entryCSN']))
    print(decode(entry['creatorsName']))
    print(decode(entry['createTimestamp']))
    print(decode(entry['modifyTimestamp']))
    print(decode(entry['modifiersName']))
    # end use PostRead Control


async def example_ldap_pre_read_control(conn, base_dn):
    # use PreRead Control
    from freeiam.ldap.controls import Controls, pre_read

    pre_read_control = pre_read(
        [
            '*',  # every regular attribute
            '+',  # every operational attribute (metadata)
        ],
        criticality=True,
    )
    controls = Controls([pre_read_control])
    dn = f'uid=max.mustermann,{base_dn}'
    result = await conn.modify(dn, ..., controls=controls)
    entry = result.controls.get(pre_read_control).entry
    # the attributes prior modification were:
    print(decode(entry['sn']))
    # end use PreRead Control


def example_set_connection_server_controls(conn, base_dn):
    # use connection wide control
    # set controls for every operation on the connection
    from freeiam.ldap.controls import Controls, pre_read

    dn = f'cn=user02,ou=users,{base_dn}'
    ctrl = pre_read(['givenName'], criticality=True)
    conn.set_controls(Controls([ctrl]))

    result = conn.modify_ml(dn, [(Mod.Replace, 'givenName', b'Foo')])
    preread = result.controls.get(ctrl)
    assert not preread.entry.get('givenName')

    result = conn.modify_ml(dn, [(Mod.Replace, 'givenName', b'Test')])
    preread = result.controls.get(ctrl)
    assert preread.entry['givenName'][0] == b'Foo'

    # unset via empty list
    conn.set_controls(Controls([]))
    # end use connection wide control


def example_error_handling(conn, base_dn):
    # start error handling
    try:
        ...  # some operation
    except errors.UnavailableCriticalExtension:
        ...  # make sure you handle unavailable extensions
        ...  # when marked with criticality=True
    # end error handling


def example_assertion_control(conn, base_dn):
    # use Assertion Control
    from freeiam.ldap.controls import Controls, assertion

    dn = f'cn=user01,ou=users,{base_dn}'
    ctrl = assertion('(sn=Bar1)', criticality=True)
    conn.modify_ml(dn, [(Mod.Replace, 'sn', b'Foo1')], controls=Controls([ctrl]))

    ctrl = assertion('(sn=Bar1)', criticality=True)
    try:
        conn.modify_ml(dn, [(Mod.Replace, 'sn', b'Foo2')], controls=Controls([ctrl]))
    except errors.AssertionFailed:
        ...  # this assertion is not True
        ...  # do something
    # end use Assertion Control


def example_get_effective_rights(conn, base_dn):
    # use GetEffectiveRights Control
    from freeiam.ldap.controls import Controls, get_effective_rights

    ctrl = get_effective_rights(conn.whoami(), criticality=True)
    result = conn.get(f'cn=user02,ou=users,{base_dn}', controls=Controls([ctrl]))
    print(result.attr['entryLevelRights'])
    print(result.attr['attributeLevelRights'])
    # end use GetEffectiveRights Control


def example_authorization_identity(conn, base_dn):
    # use Authorization Identity Control
    from freeiam.ldap.controls import Controls, authorization_identity
    from freeiam.ldap.dn import DN

    ctrl = authorization_identity(criticality=True)
    result = conn.bind(
        f'uid=testuser,ou=users,{base_dn}', 'secret', controls=Controls([ctrl])
    )
    res = result.controls.get(authorization_identity.response)
    dn = res.authzId.decode('UTF-8')
    if dn.startswith('dn:'):
        DN(dn.removeprefix('dn:'))
    # end use Authorization Identity Control


def example_dereference(conn, base_dn):
    # use Dereference Control (not supported by OpenLDAP)
    from freeiam.ldap.controls import Controls, dereference

    ctrl = dereference({'member': 'cn'}, criticality=True)
    conn.search(
        f'ou=groups,{base_dn}',
        Scope.Subtree,
        '(objectClass=groupOfNames)',
        controls=Controls([ctrl]),
    )
    # end use Dereference Control (not supported by OpenLDAP)


def example_matched_values(conn, base_dn):
    # use MatchedValues Control
    from freeiam.ldap.controls import Controls, matched_values

    ctrl = matched_values('(sn=Muster*)', criticality=True)
    results = conn.search(
        f'ou=users,{base_dn}',
        Scope.Subtree,
        '(objectClass=inetOrgPerson)',
        controls=Controls([ctrl]),
    )
    print([obj.attr['sn'] for obj in results])  # contains only 'sn' attributes
    # end use MatchedValues Control


def example_persistent_search(conn, base_dn):
    # use PersistentSearch Control (not supported by OpenLDAP)
    from freeiam.ldap.controls import Controls, persistent_search

    ctrl = persistent_search(
        [LDAPChangeType.Modify],
        changes_only=True,
        return_entry_change_control=True,
        criticality=True,
    )
    # this blocks until any of the entry is modified!
    conn.search(
        f'ou=users,{base_dn}',
        Scope.Subtree,
        '(objectClass=inetOrgPerson)',
        controls=Controls([ctrl]),
    )
    # end use PersistentSearch Control (not supported by OpenLDAP)


def example_session_tracking(conn, base_dn):
    # use SessionTrackingControl (not supported by OpenLDAP)
    from freeiam.ldap.controls import Controls, session_tracking

    ctrl = session_tracking(
        '127.0.0.1', 'test-client', '1.3.6.1.4.1.1466.115.121.1.15', 'Max.Mustermann'
    )
    conn.search(base_dn, Scope.Base, '(objectClass=*)', controls=Controls([ctrl]))
    # end use SessionTrackingControl (not supported by OpenLDAP)


def example_manage_dsa_information_tree(conn, base_dn):
    # use ManageDSAITControl
    from freeiam.ldap.controls import Controls, manage_dsa_information_tree

    ctrl = manage_dsa_information_tree(criticality=True)
    conn.search(f'{base_dn}', Scope.Base, '(objectClass=*)', controls=Controls([ctrl]))
    # end use ManageDSAITControl


def example_relax_rules(conn, base_dn):
    # use RelaxRules Control
    from freeiam.ldap.controls import Controls, relax_rules

    ctrl = relax_rules(criticality=True)
    custom_entry_uuid = b'00000000-0000-0000-0000-000000000000'
    conn.modify_ml(
        f'cn=user01,ou=users,{base_dn}',
        [(Mod.Replace, 'entryUUID', custom_entry_uuid)],
        controls=Controls([ctrl]),
    )
    assert conn.get_attr(f'cn=user01,ou=users,{base_dn}', 'entryUUID') == [
        custom_entry_uuid
    ]
    # end use RelaxRules Control


def example_proxy_authorization(conn, base_dn):
    # use ProxyAuthz Control
    from freeiam.ldap.controls import Controls, proxy_authorization
    from freeiam.ldap.dn import DN

    ctrl = proxy_authorization(DN(f'cn=admin,{base_dn}'), criticality=True)
    conn.search(f'{base_dn}', Scope.Base, '(objectClass=*)', controls=Controls([ctrl]))
    # end use ProxyAuthz Control
