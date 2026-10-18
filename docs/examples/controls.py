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
    # use Dereference Control
    from freeiam.ldap.controls import Controls, dereference

    ctrl = dereference(
        {'member': ['mail', 'displayName', 'entryUUID']}, criticality=True
    )
    entries = conn.search(
        f'ou=groups,{base_dn}',
        Scope.Subtree,
        '(objectClass=groupOfNames)',
        controls=Controls([ctrl]),
    )

    for entry in entries:
        response = entry.controls.get(dereference.response)

        if response is None:
            continue

        print('Group: {entry.dn}')
        for member_dn, attrs in response.refs['member'].items():
            print(f'  Member: {member_dn}')
            print(f'    Email: {attrs["mail"][0].decode("utf-8")}')
            print(f'    Name:  {attrs["displayName"][0].decode("utf-8")}')
            print(f'    UUIID:  {attrs["entryUUID"][0].decode("utf-8")}')

    # end use Dereference Control


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


def example_search_no_op(conn, base_dn):
    # use Search No-Op Control directly to count matching entries without returning them
    # prefer conn.count() for this use case
    from freeiam.ldap.controls import Controls, search_no_op

    ctrl = search_no_op(criticality=True)
    controls = Controls([ctrl])
    next(
        conn.search_dn(
            f'ou=users,{base_dn}',
            Scope.Subtree,
            '(objectClass=inetOrgPerson)',
            controls=controls,
        ),
        None,
    )

    noop_response = controls.get(ctrl)
    assert noop_response is not None
    print(noop_response.numSearchResults)
    print(noop_response.numSearchContinuations)
    # end use Search No-Op Control


def example_password_policy(conn, base_dn):
    # use Password Policy control
    from ldap.controls.ppolicy import PasswordPolicyError

    from freeiam.ldap.controls import Controls, password_policy

    dn = f'cn=user01,ou=users,{base_dn}'
    ctrl = password_policy(criticality=True)
    controls = Controls([ctrl])

    try:
        result = conn.bind(dn, 'secret', controls=controls)
    except errors.InvalidCredentials as exc:
        # Failed authentication: password-policy errors are attached to the exception
        policy = Controls(response=exc.controls).get(password_policy())
        if policy is not None and policy.error is not None:
            print(PasswordPolicyError(policy.error).prettyPrint())
    else:
        # Successful authentication: inspect password warnings
        policy = result.controls.get(ctrl)
        if policy is not None and policy.error is None:
            print(policy.timeBeforeExpiration)
            print(policy.graceAuthNsRemaining)

    try:
        result = conn.change_password(dn, 'secret', 'too-short', controls=controls)
    except errors.ConstraintViolation as exc:
        # Failed password change: password-policy errors are attached to the exception
        policy = Controls(response=exc.controls).get(password_policy())
        if policy is not None and policy.error is not None:
            print(PasswordPolicyError(policy.error).prettyPrint())
    # end use Password Policy control


def example_netscape_password_status_controls(conn, base_dn):
    # use Netscape password status controls
    from freeiam.ldap.controls import password_expired, password_expiring

    result = conn.bind(f'cn=user01,ou=users,{base_dn}', 'iamfree1')

    expired = result.controls.get(password_expired())
    if expired is not None:
        print(expired.passwordExpired)

    expiring = result.controls.get(password_expiring())
    if expiring is not None:
        print(expiring.gracePeriod)
    # end use Netscape password status controls


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
    # use SessionTrackingControl
    from freeiam.ldap.constants import SessionTrackingFormat
    from freeiam.ldap.controls import Controls, session_tracking

    ip = '192.0.2.1'
    host = 'app.freeiam.org'
    ctrls = [
        session_tracking(
            ip,
            host,
            SessionTrackingFormat.RadiusAcctSessionID,
            '{Acct-Session-Id RADIUS attribute}',
        ),
        session_tracking(
            ip,
            host,
            SessionTrackingFormat.RadiusAcctMultiSessionID,
            '{Acct-Multi-Session-Id RADIUS attribute}',
        ),
        session_tracking(
            ip,
            host,
            SessionTrackingFormat.Username,
            '{username (SASL authorization identity)}',
        ),
    ]
    conn.search(base_dn, Scope.Base, '(objectClass=*)', controls=Controls(ctrls))
    # end use SessionTrackingControl


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
