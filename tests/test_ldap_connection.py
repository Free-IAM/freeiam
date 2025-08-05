import asyncio
import contextlib
import inspect
import logging
import math
import pickle

import ldap as _ldap
import pytest
import pytest_asyncio

from freeiam import errors, ldap
from freeiam.ldap.constants import Dereference, Option, OptionValue, Scope, TLSOptionValue, Version
from freeiam.ldap.controls import Controls, virtual_list_view


log = logging.getLogger(__name__)


TESTUSERNAME = 'testuser'
TESTUSERNAME_B = TESTUSERNAME.encode()
PAGEPREFIX = 'page'
NUM_PAGEUSERS = 13


@pytest_asyncio.fixture(scope='function')
async def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn


@pytest_asyncio.fixture(scope='session')
async def sess_conn(ldap_server, base_dn):
    """
    A session scoped fixture which should only be used by other fixtures.

    Use it to make initial setup as it can loose its connection and become stale.
    """
    async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn


async def create_ou(conn, dn):
    name = ldap.DN.get(dn).rdn[1]
    with contextlib.suppress(errors.AlreadyExists):
        await conn.add(dn, {'objectClass': [b'top', b'organizationalUnit'], 'ou': [name.encode()]})


async def create_user(conn, dn, **kw):
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
        await conn.add(dn, attrs)
    return dn, attrs


@pytest_asyncio.fixture(scope='session')
async def testuser(sess_conn, base_dn):
    """A testuser which exist the whole session"""
    return await create_user(sess_conn, f'cn={TESTUSERNAME},{base_dn}', sn='User')


@pytest_asyncio.fixture(scope='function')
async def testuser2(sess_conn, base_dn):
    """A testuser which can be destroyed"""
    dn, _attrs = await create_user(sess_conn, f'cn={TESTUSERNAME}2,{base_dn}', sn='User')
    yield dn
    with contextlib.suppress(errors.NoSuchObject):
        await sess_conn.delete(dn)


@pytest_asyncio.fixture(scope='session')
async def ou_structure(sess_conn, base_dn):
    dn = ldap.DN(f'cn={TESTUSERNAME}3,ou=Newsletter,ou=Marketing,ou=Departments,{base_dn}')
    dn2 = ldap.DN(f'cn={TESTUSERNAME}4,ou=Sales,ou=Departments,{base_dn}')
    base = dn.parent.parent.parent
    await create_ou(sess_conn, base)
    await create_ou(sess_conn, dn.parent.parent)
    await create_ou(sess_conn, dn.parent)
    await create_ou(sess_conn, dn2.parent)
    await create_user(sess_conn, dn)
    await create_user(sess_conn, dn2)
    return base


@pytest.mark.asyncio
async def test_unconnected_error(ldap_server):
    conn = ldap.Connection(ldap_server['ldap_uri'])
    with pytest.raises(RuntimeError):
        conn.conn  # noqa: B018
    await conn.unbind()
    assert (await conn.whoami()) is None


def test_sync_usage(ldap_server):
    with ldap.Connection(ldap_server['ldap_uri']) as conn:
        conn.conn.whoami_s()


@pytest.mark.asyncio
async def test_whoami(conn, base_dn):
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'


@pytest.mark.asyncio
async def test_reconnect(conn, base_dn):
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    log.info('FD: %s', conn.fileno)
    conn.reconnect()
    log.info('Reconnected: %s', conn.fileno)
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    assert await conn.get(base_dn)


def test_get_and_set_option(conn):
    assert conn.get_option(Option.Referrals) == -1
    conn.set_option(Option.Referrals, 0)
    assert conn.get_option(Option.Referrals) == OptionValue.Off
    conn.set_option(Option.Referrals, -1)

    conn.protocol_version = Version.LDAPV3
    assert conn.protocol_version == Version.LDAPV3

    assert conn.sizelimit == OptionValue.NoLimit
    conn.sizelimit = 20

    assert conn.network_timeout is None
    conn.network_timeout = 50
    assert conn.network_timeout == 50  # noqa: PLR2004

    assert conn.timelimit == OptionValue.NoLimit
    conn.timelimit = 20

    assert conn.dereference == Dereference.Never
    conn.dereference = Dereference.Always
    assert conn.dereference == Dereference.Always

    assert conn.follow_referrals is None
    conn.follow_referrals = False
    assert conn.follow_referrals is False

    conn.follow_referrals = True
    # FIXME: not supported by server?: assert conn.follow_referrals is True

    stats = 256
    conn.set_global_option(Option.DebugLevel, stats)
    assert conn.get_global_option(Option.DebugLevel) == stats

    conn.set_controls(Controls(None, []))
    assert conn.get_option(Option.ServerControls) == []
    assert conn.get_option(Option.ClientControls) == []

    conn.set_controls(Controls([], None))
    assert conn.get_option(Option.ServerControls) == []
    assert conn.get_option(Option.ClientControls) == []


def test_error_wrap():
    with pytest.raises(errors.Timeout), errors.LdapError.wrap(hide_parent_exception=False):
        raise _ldap.TIMEOUT()


@pytest.mark.asyncio
async def test_error_handling_no_object(conn, testuser):
    with pytest.raises(errors.NoSuchObject) as err:
        await conn.get('cn=notexists,dc=FreeIAM,dc=Org')

    exc = err.value
    assert exc.description == 'No such object'
    assert exc.matched == 'dc=freeiam,dc=org'
    assert exc.info is None
    assert exc.errno is None
    assert exc.result == 32  # noqa: PLR2004
    assert exc.controls == []
    assert repr(exc).startswith("NoSuchObject(description='No such object', info=None, matched='dc=freeiam,dc=org', result=32, errno=None, base_dn=")

    assert conn.get_option(Option.ErrorNumber) == 32  # noqa: PLR2004
    assert not conn.get_option(Option.ErrorString)
    assert conn.get_option(Option.MatchedDN) == 'dc=freeiam,dc=org'

    with pytest.raises(errors.NoSuchObject) as exc:
        async for _ in conn.search_iter('cn=notexists,dc=FreeIAM,dc=Org'):
            pass


@pytest.mark.asyncio
async def test_error_handling_exists(conn, testuser):
    with pytest.raises(errors.AlreadyExists) as exc:
        await conn.add(testuser[0], testuser[1])
    assert exc.value.description == 'Already exists'


@pytest.mark.asyncio
async def test_error_handling_rename_violation(conn, testuser):
    with pytest.raises(errors.ObjectClassViolation) as exc:
        await conn.rename(testuser[0], f'uid={testuser[0].removeprefix("cn=")}', delete_old=True)
    assert exc.value.description == 'Object class violation'
    assert exc.value.info == "object class 'inetOrgPerson' requires attribute 'cn'"


@pytest.mark.asyncio
async def test_error_handling_invalid_dn(conn, testuser):
    with pytest.raises(errors.InvalidDN):
        async for _ in conn.search_iter('foo'):
            pass


@pytest.mark.asyncio
async def test_error_handling_invalid_filter(conn, testuser):
    # this tests exception handling in result4()
    with pytest.raises(errors.FilterError):
        async for _ in conn.search_iter('cn=foo', 1, 'bar'):
            pass


def test_error_handling_duplicate_connect(conn):
    with pytest.raises(RuntimeError):
        conn.connect()


@pytest.mark.asyncio
async def test_get(conn, testuser):
    dn, attr = testuser
    result = await conn.get(dn)
    assert result.dn == dn
    assert result.attr == attr


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


@pytest.mark.asyncio
async def test_exists(conn, testuser):
    assert await conn.exists(testuser[0])
    assert not await conn.exists('cn=notexists,dc=FreeIAM,dc=Org')


@pytest.mark.asyncio
async def test_search(conn, testuser, base_dn):
    dn, attrs = testuser

    filter_s = f'(cn={TESTUSERNAME})'
    result = [entry async for entry in conn.search_iter(base_dn, Scope.SUBTREE, filter_s)]
    assert len(result) == 1
    result = result[0]
    assert result.dn == dn, result.dn
    assert result.attr == attrs, result.attr

    result = [entry async for entry in conn.search_dn(base_dn, Scope.SUBTREE, filter_s)]
    assert result == [dn], result

    (result,) = await conn.search(base_dn, Scope.SUBTREE, filter_s)


@pytest.mark.asyncio
async def test_sorting_search(conn, testuser, base_dn):
    filter_s = f'(cn={TESTUSERNAME}*)'
    result = list(reversed([entry async for entry in conn.search_dn(base_dn, Scope.SUBTREE, filter_s)]))
    sresult = [entry.dn async for entry in conn.search_iter(base_dn, Scope.SUBTREE, filter_s, sorting=[('cn', 'caseIgnoreOrderingMatch', True)])]
    assert result == sresult

    sresult2 = [entry.dn for entry in await conn.search(base_dn, Scope.SUBTREE, filter_s, sorting=[('cn', 'caseIgnoreOrderingMatch', True)])]
    assert result == sresult2

    sresult3 = [entry async for entry in conn.search_dn(base_dn, Scope.SUBTREE, filter_s, sorting=['-cn:caseIgnoreOrderingMatch'])]
    assert result == sresult3

    sresult4 = [entry.dn async for entry in conn.search_paged(base_dn, Scope.SUBTREE, filter_s, sorting=[('cn', 'caseIgnoreOrderingMatch', True)])]
    assert result == sresult4


@pytest.mark.asyncio
async def test_modify(conn, testuser):
    dn, attrs = testuser

    newattrs = attrs.copy()
    newattrs.update(
        {
            'sn': [b'New User'],
            'givenName': [b'Name'],
        }
    )
    await conn.modify(dn, attrs, newattrs)
    result = await conn.get(dn)
    assert result.attr == newattrs, result.attr


@pytest.mark.asyncio
async def test_get_attr(conn, testuser):
    dn = testuser[0]
    result = await conn.get_attr(dn, 'uid')
    assert result == [TESTUSERNAME_B]


@pytest.mark.asyncio
async def test_get_attr_not_existing(conn, testuser):
    dn = testuser[0]
    with pytest.raises(KeyError):
        await conn.get_attr(dn, 'foo')


@pytest.mark.asyncio
async def test_get_attr_case(conn, testuser):
    dn = testuser[0]
    result = await conn.get_attr(dn, 'Uid')
    assert result == [TESTUSERNAME_B]


@pytest.mark.asyncio
async def test_get_attr_alias(conn, testuser):
    dn = testuser[0]
    result = await conn.get_attr(dn, 'commonName')
    assert result == [TESTUSERNAME_B]


@pytest.mark.asyncio
async def test_get_schema(conn):
    schema = await conn.get_schema()
    assert schema, schema


@pytest.mark.asyncio
async def test_get_schema_not_existing(conn):
    schema = await conn.get_schema(await conn.whoami())
    assert schema, schema


@pytest.mark.asyncio
async def test_get_schema_no_schema_object(conn, testuser):
    schema = await conn.get_schema(testuser[0])
    assert schema, schema


@pytest.mark.asyncio
async def test_get_schema_cache(conn, base_dn):
    schema = await conn.get_schema()
    assert schema, schema
    assert (await conn.get_schema()) is schema
    conn.reconnect()
    assert (await conn.get_schema()) is not schema


@pytest.mark.asyncio
async def test_modify_rename(conn, testuser2, base_dn):
    result = await conn.modify_ml(testuser2, [(_ldap.MOD_REPLACE, 'cn', [f'{TESTUSERNAME}3'.encode()])])
    assert result.dn == f'cn={TESTUSERNAME}3,{base_dn}'


@pytest.mark.asyncio
async def test_rename(conn, testuser2, base_dn):
    dn = (await conn.rename(testuser2, f'cn={TESTUSERNAME}4,{base_dn}')).dn
    assert dn == f'cn={TESTUSERNAME}4,{base_dn}'


@pytest.mark.asyncio
async def test_move(conn, testuser2, base_dn):
    dn = f'ou=Engineering,{base_dn}'
    await create_ou(conn, dn)
    result = await conn.move(testuser2, dn)
    assert result.dn == f'cn={TESTUSERNAME}2,{dn}'


@pytest.mark.asyncio
async def test_rename_rdn(conn, testuser2, base_dn):
    dn = (await conn.modrdn(testuser2, f'uid={TESTUSERNAME}5', delete_old=False)).dn
    assert dn == f'uid={TESTUSERNAME}5,{base_dn}'


@pytest.mark.asyncio
async def test_rename_only_rdn(conn, testuser2, base_dn):
    dn = (await conn.rename(testuser2, f'uid={TESTUSERNAME}2,{base_dn}', delete_old=False)).dn
    assert dn == f'uid={TESTUSERNAME}2,{base_dn}'


@pytest.mark.asyncio
async def test_rename_multi_rdn(conn, testuser2, base_dn):
    dn = (await conn.rename(testuser2, f'uid={TESTUSERNAME}2+cn={TESTUSERNAME}2,{base_dn}')).dn
    assert dn == f'uid={TESTUSERNAME}2+cn={TESTUSERNAME}2,{base_dn}'


@pytest.mark.asyncio
async def test_remove(conn, testuser2):
    await conn.delete(testuser2)
    with pytest.raises(errors.NoSuchObject):
        await conn.get(testuser2)


@pytest.mark.asyncio
@pytest.mark.timeout(10)
async def test_remove_recursive(conn, ou_structure):
    await conn.delete_recursive(ou_structure)
    with pytest.raises(errors.NoSuchObject):
        await conn.get(ou_structure)


@pytest.mark.asyncio
async def test_unbind(conn):
    await conn.unbind()
    assert not (await conn.whoami())


@pytest.mark.asyncio
async def test_duplicated_unbind(conn):
    await conn.unbind()
    await conn.unbind()
    assert not (await conn.whoami())


@pytest_asyncio.fixture(scope='session')
async def page_users(sess_conn, base_dn):
    results = []
    for i in range(1, NUM_PAGEUSERS + 1):
        dn = f'cn={PAGEPREFIX}user{i},{base_dn}'
        await create_user(sess_conn, dn, sn='User')
        results.append(dn)
    yield tuple(results)


@pytest.mark.asyncio
async def test_paginated_search(conn, page_users, base_dn):
    results = sorted(page_users)
    page_size = 6
    total_pages = math.ceil(len(results) / page_size)
    total_entries = 0
    cur_entry_on_page = 1
    async for entry in conn.search_paginated(
        base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', page_size=page_size, sorting=[('cn', 'caseIgnoreOrderingMatch', False)]
    ):
        assert results.pop(0) == entry.dn

        assert entry.page.page_size == page_size
        assert entry.page.page == (1 + total_entries // page_size)
        assert entry.page.is_last_in_page == (page_size == entry.page.entry)
        assert entry.page.entry == cur_entry_on_page
        assert entry.page.results == NUM_PAGEUSERS
        assert entry.page.last_page is total_pages

        total_entries += 1
        cur_entry_on_page += 1
        if entry.page.is_last_in_page:
            cur_entry_on_page = 1

    assert not results, results
    assert total_entries == NUM_PAGEUSERS


@pytest.mark.asyncio
async def test_paginated_error_search(conn, page_users, base_dn):
    pagination = virtual_list_view(
        before_count=0,
        after_count=100,
        offset=0,
        content_count=0,
        greater_than_or_equal=None,
        context_id=None,
        criticality=True,
    )
    controls = Controls.set_server(None, pagination)
    await conn.search(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', sorting=[('cn', 'caseIgnoreOrderingMatch', False)], controls=controls)
    res = controls.get(virtual_list_view.response())
    pagination.context_id = res.context_id
    pagination.offset = res.contentCount + 1
    with pytest.raises(errors.VLVError) as exc:
        await conn.search(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', sorting=[('cn', 'caseIgnoreOrderingMatch', False)], controls=controls)
    assert exc.value.controls[0].result == 77  # noqa: PLR2004


@pytest.mark.asyncio
async def test_paginated_search_expect_nothing(conn, base_dn):
    async for entry in conn.search_paginated(
        base_dn, Scope.SUBTREE, '(cn=doesnotexists)', page_size=5, sorting=[('cn', 'caseIgnoreOrderingMatch', False)]
    ):
        pytest.fail(f'Got {entry}')


@pytest.mark.asyncio
async def test_paged_search(conn, page_users, base_dn):
    results = list(page_users)
    page_size = 5
    total_entries = 0
    cur_entry_on_page = 1
    async for entry in conn.search_paged(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', page_size=page_size):
        assert results.pop(0) == entry.dn

        assert entry.page.page_size == page_size
        assert entry.page.page == (1 + total_entries // page_size)
        assert entry.page.is_last_in_page == (page_size == entry.page.entry)
        assert entry.page.entry == cur_entry_on_page
        assert entry.page.results is None
        assert entry.page.last_page is None

        total_entries += 1
        cur_entry_on_page += 1
        if entry.page.is_last_in_page:
            cur_entry_on_page = 1

    assert not results, results
    assert total_entries == NUM_PAGEUSERS


@pytest.mark.asyncio
async def test_paged_search_expect_nothing(conn, base_dn):
    async for entry in conn.search_paged(base_dn, Scope.SUBTREE, '(cn=doesnotexists)', page_size=5):
        pytest.fail(f'Got {entry}')


@pytest.mark.asyncio
async def test_unique_search(conn, page_users, base_dn):
    assert len(page_users) > 1
    with pytest.raises(errors.NotUnique) as exc:
        [entry async for entry in conn.search_iter(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', unique=True)]
    assert exc.value.results

    with pytest.raises(errors.NotUnique) as exc:
        await conn.search(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', unique=True)
    assert exc.value.results

    with pytest.raises(errors.NotUnique) as exc:
        [entry async for entry in conn.search_dn(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', unique=True)]
    assert exc.value.results


@pytest.mark.asyncio
async def test_is_pickleable(conn, base_dn):
    # FIXME: hangs
    # num = 50
    # conn.set_option(Option.Sizelimit, num)
    # conn.timelimit = num
    conn.dereference = Dereference.Always
    pickle_bytes = pickle.dumps(conn)
    log.info('Pickle: %s', pickle_bytes)
    conn = pickle.loads(pickle_bytes)
    assert conn.dereference == Dereference.Always
    # assert conn.get_option(Option.Sizelimit) == num
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'


@pytest.mark.asyncio
async def test_unbound_is_pickleable(ldap_server, base_dn):
    conn = ldap.Connection(ldap_server['ldap_uri'])
    conn = pickle.loads(pickle.dumps(conn))
    assert not (await conn.whoami())

    conn.connect()
    await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'

    await conn.unbind()


@pytest.mark.asyncio
async def test_naming_context(conn, base_dn):
    assert [base_dn] == await conn.get_naming_contexts()


@pytest.mark.asyncio
async def test_root_dse(conn):
    dse = await conn.get_root_dse()
    assert set(dse.attr.keys()) == {
        'configContext',
        'entryDN',
        'monitorContext',
        'namingContexts',
        'objectClass',
        'structuralObjectClass',
        'subschemaSubentry',
        'supportedControl',
        'supportedExtension',
        'supportedFeatures',
        'supportedLDAPVersion',
        # 'supportedSASLMechanisms',
    }


@pytest.mark.asyncio
async def _test_error_no_results_returned(conn):
    # result = await conn.get(await conn.whoami())result.response.msgid):
    msgid = 42
    async for _response in conn._wait(conn.conn, msgid):
        pass


@pytest.mark.asyncio
async def test_no_reconnect(ldap_server, base_dn):
    conn = ldap.Connection(ldap_server['ldap_uri'], automatic_reconnect=False)
    conn.connect()
    await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    await conn.unbind()


@pytest.mark.asyncio
async def test_ldap_plaintext(ldap_server, base_dn):
    conn = ldap.Connection(ldap_server['ldap_uri'])
    conn.connect()
    await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    await conn.unbind()


@pytest.mark.tls
@pytest.mark.asyncio
async def test_starttls_explicit(ldap_server, base_dn):
    ldap.Connection.set_tls(ca_certfile=ldap_server['ca_cert'], require_cert=TLSOptionValue.Allow)
    conn = ldap.Connection(ldap_server['ldap_uri'])
    conn.connect()
    conn.start_tls()
    await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    await conn.unbind()


@pytest.mark.tls
@pytest.mark.asyncio
async def test_starttls_reconnect(ldap_server, base_dn):
    ldap.Connection.set_tls(ca_certfile=ldap_server['ca_cert'], require_cert=TLSOptionValue.Allow)
    conn = ldap.Connection(ldap_server['ldap_uri'], start_tls=True)
    conn.connect()
    await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    conn.reconnect()
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    assert await conn.get(base_dn)
    await conn.unbind()


@pytest.mark.tls
@pytest.mark.asyncio
async def test_starttls(ldap_server, base_dn):
    ldap.Connection.set_tls(ca_certfile=ldap_server['ca_cert'], require_cert=TLSOptionValue.Allow)
    conn = ldap.Connection(ldap_server['ldap_uri'], start_tls=True)
    conn.connect()
    await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    await conn.unbind()


@pytest.mark.tls
@pytest.mark.asyncio
async def test_ldaps(ldap_server, base_dn):
    ldap.Connection.set_tls(ca_certfile=ldap_server['ca_cert'], require_cert=TLSOptionValue.Allow)
    conn = ldap.Connection(ldap_server['ldaps_uri'], timeout=5)
    conn.connect()
    await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
    assert (await conn.whoami()) == f'cn=admin,{base_dn}'
    await conn.unbind()


@pytest.mark.xfail(raises=errors.UnwillingToPerform, reason='Container setup')
@pytest.mark.asyncio
async def test_change_password(ldap_server, conn, base_dn):
    with pytest.raises(errors.UnwillingToPerform) as exc:
        assert await conn.change_password(ldap_server['bind_dn'], 'foo', 'bar')
    assert exc.value.info == 'unwilling to verify old password'

    new_password = 'thisisaverydangeroustests'  # noqa: S105
    assert await conn.change_password(ldap_server['bind_dn'], ldap_server['bind_pw'], new_password)
    assert await conn.change_password(ldap_server['bind_dn'], new_password, ldap_server['bind_pw'])


@pytest.mark.asyncio
async def test_paginated_search_close(conn, page_users, base_dn):
    gen = conn.search_paginated(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', page_size=1, sorting=[('uid', 'caseIgnoreOrderingMatch', False)])

    result = await anext(gen)
    assert result is not None

    await gen.aclose()

    with pytest.raises(StopAsyncIteration):
        await anext(gen)


@pytest.mark.asyncio
async def test_paged_search_close(conn, page_users, base_dn):
    gen = conn.search_paged(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)', page_size=1)

    result = await anext(gen)
    assert result is not None

    await gen.aclose()

    with pytest.raises(StopAsyncIteration):
        await anext(gen)


@pytest.mark.xfail(raises=_ldap.PROTOCOL_ERROR, match='unsupported extended operation', reason='LDAP Test setup')
@pytest.mark.timeout(5)  # used to block when msgid == None was not handled
@pytest.mark.asyncio
async def test_cancel(conn, page_users, base_dn):
    msgid = conn.conn.add_ext(str(base_dn), [])
    assert msgid
    with pytest.raises(errors.NoSuchOperation):
        await conn.cancel(msgid)

    assert conn.conn.result4(msgid, all=1, timeout=1)


@pytest.mark.asyncio
async def test_cancel_unbound(conn):
    res = await conn.unbind()
    conn.disconnect()
    assert await conn.cancel(res._response.msgid) is False


@pytest.mark.timeout(5)  # used to block when msgid == None was not handled
@pytest.mark.asyncio
async def test_abandon(conn, page_users, base_dn):
    msgid = conn.conn.add_ext(str(base_dn), [])
    assert msgid
    await conn.abandon(msgid)
    with pytest.raises(_ldap.TIMEOUT):
        assert conn.conn.result4(msgid, all=1, timeout=1)


@pytest.mark.timeout(5)  # used to block when msgid == None was not handled
@pytest.mark.asyncio
async def test_abandon_iter(conn, page_users, base_dn):
    msgid = conn.conn.add_ext(str(base_dn), [])
    assert msgid
    async for result in conn._execute_iter(conn.conn, conn.conn.abandon_ext, msgid):
        assert not result


# @pytest.mark.timeout(5)  # used to block when msgid == None was not handled
# def test_abandon_s(conn, page_users, base_dn):
#     msgid = conn.conn.add_ext(str(base_dn), [])
#     assert msgid
#     conn._execute_s(conn.conn, conn.conn.abandon_ext, msgid)
#
#
# @pytest.mark.asyncio
# async def test_parallelism(conn, page_users, base_dn):
#    async for result in conn.search_iter(base_dn, Scope.SUBTREE, f'(cn={PAGEPREFIX}*)'):
#        await conn.get(result.dn)


@pytest.mark.xfail(raises=errors.ProtocolError, match='unsupported extended operation', reason='LDAP Test setup')
@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_extop(conn, base_dn):
    from ldap.extop.dds import RefreshRequest, RefreshResponse

    req = RefreshRequest(RefreshRequest.requestName, base_dn, RefreshRequest.defaultRequestTtl)
    req.requestValue = b''
    await conn.extop(req, RefreshResponse)


def test_sync_methods_exists():
    def methods(cls):
        return {name for name, member in inspect.getmembers(cls, predicate=inspect.isfunction) if not name.startswith('_')}

    missing = methods(ldap.Connection) - methods(ldap.connection.SynchronousConnection) - {'cancel_s', 'unbind_s'}
    assert not missing, f'Methods missing in sync_connection.Connection: {missing}'


@pytest.mark.asyncio
async def test_retry_error(ldap_server):
    def func():
        with errors.LdapError.wrap():
            conn.conn.search_ext_s('', 1)  # fake LDAP server down

    async with ldap.Connection('', automatic_reconnect=True, max_connection_attempts=2, retry_delay=0.5) as conn:
        with pytest.raises(errors.ServerDown):
            await conn._retry(func)


@pytest.mark.asyncio
async def test_retry_success(ldap_server):
    attemps = 3
    i = {'i': attemps}

    def func():
        i['i'] -= 1
        if not i['i']:
            return True
        with errors.LdapError.wrap():
            conn.conn.search_ext_s('', 1)  # fake LDAP server down
            return False

    class Connection(ldap.Connection):
        def reconnect(self, *a, **k):
            pass

    async with Connection('', automatic_reconnect=True, max_connection_attempts=attemps, retry_delay=0.5) as conn:
        assert await conn._retry(func)


@pytest.mark.skip
@pytest.mark.asyncio
async def test_automatic_reconnect(ldap_server, base_dn):
    async with ldap.Connection(ldap_server['ldap_uri'], automatic_reconnect=True, max_connection_attempts=2, retry_delay=0.5) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        ldap_server['stop']()

        try:
            await asyncio.sleep(3)

            with pytest.raises(errors.ServerDown):
                await conn.get(base_dn)
        finally:
            ldap_server['start']()

        await asyncio.sleep(10)

        conn.reconnect()
        assert (await conn.whoami()) == f'cn=admin,{base_dn}'
        assert await conn.get(base_dn)


def test_end_teardown():
    pass  # catches general pytest exceptions
