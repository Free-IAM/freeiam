import asyncio
import multiprocessing
import os

import pytest
import pytest_asyncio

from freeiam import ldap
from freeiam.ldap.constants import Scope


num_workers = min(os.cpu_count(), 4)
total_iterations = 100
iterations_per_worker = total_iterations // num_workers


class Client:
    """Abstract base client"""

    def __init__(self, conn):
        self.conn = conn

    async def search(self, *args, **kwargs):  # noqa: PLR6301
        pytest.skip('search not implemented')

    async def search_iter(self, *args, **kwargs):  # noqa: PLR6301
        pytest.skip('search_iter not implemented')

    def search_s(self, *args, **kwargs):  # noqa: PLR6301
        pytest.skip('search_s not implemented')

    def search_iter_s(self, *args, **kwargs):  # noqa: PLR6301
        pytest.skip('search_iter_s not implemented')


class FreeIAMClient(Client):
    """freeiam"""

    async def search(self, *args, **kwargs):
        return await self.conn.search(*args, **kwargs)

    async def search_iter(self, *args, **kwargs):
        return [x async for x in self.conn.search_iter(*args, **kwargs)]

    def search_s(self, *args, **kwargs):
        return self.conn.search(*args, **kwargs)

    def search_iter_s(self, *args, **kwargs):
        return list(self.conn.search_iter(*args, **kwargs))


class BonsaiClient(Client):
    """bonsai"""

    async def search(self, *args, **kwargs):
        return await self.conn.search(*args, **kwargs)

    def search_s(self, *args, **kwargs):
        return self.conn.search(*args, **kwargs)


class LDAPClient(Client):
    """ldap"""

    def search_s(self, *args, **kwargs):
        return self.conn.search_s(*args, **kwargs)


class LDAP3Client(Client):
    """ldap3"""

    def search_s(self, base, scope, filter_s, *args, **kwargs):
        self.conn.search(base, filter_s, 'SUBTREE' if scope == Scope.Subtree else 'BASE', *args, **kwargs)
        return self.conn.entries


@pytest_asyncio.fixture(params=['freeiam', 'bonsai', 'ldap', 'ldap3'])
async def async_client(request, ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    admin_dn, password = ldap_server['bind_dn'], ldap_server['bind_pw']
    if request.param == 'freeiam':
        async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1, max_connection_attempts=1, timeout=15) as conn:
            await conn.bind(admin_dn, password)
            yield FreeIAMClient(conn)
        return
    elif request.param == 'bonsai':
        import bonsai

        client = bonsai.LDAPClient(ldap_server['ldap_uri'])
        client.set_credentials('SIMPLE', user=admin_dn, password=password)
        async with client.connect(is_async=True) as conn:
            yield BonsaiClient(conn)
        return
    pytest.skip(f'Not Implemented: {request.param}')


@pytest.fixture(params=['freeiam', 'bonsai', 'ldap', 'ldap3'])
def client(request, ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account"""
    admin_dn, password = ldap_server['bind_dn'], ldap_server['bind_pw']
    if request.param == 'freeiam':
        with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1, max_connection_attempts=1, timeout=15) as conn:
            conn.bind(admin_dn, password)
            yield FreeIAMClient(conn)
        return
    elif request.param == 'bonsai':
        import bonsai

        client = bonsai.LDAPClient(ldap_server['ldap_uri'])
        client.set_credentials('SIMPLE', user=admin_dn, password=password)
        with client.connect() as conn:
            yield BonsaiClient(conn)
        return
    elif request.param == 'ldap':
        import ldap as _ldap

        client = _ldap.initialize(ldap_server['ldap_uri'])
        client.simple_bind_s(admin_dn, password)
        yield LDAPClient(client)
        client.unbind_s()
        return
    elif request.param == 'ldap3':
        from ldap3 import ALL, Connection, Server

        server = Server(ldap_server['host'], ldap_server['port_ldap'], use_ssl=False, get_info=ALL)
        conn = Connection(server, admin_dn, password, auto_bind=True)
        yield LDAP3Client(conn)
        return
    pytest.skip(f'Not Implemented: {request.param}')


@pytest.fixture(scope='session', autouse=True)
def benchmark_users(ldap_server, base_dn):
    testusername = 'benchmark-user'
    with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        for i in range(1, 21):
            dn = f'uid={testusername}{i},{base_dn}'
            attrs = {
                'objectClass': [b'inetOrgPerson'],
                'uid': [f'{testusername}{i}'.encode()],
                'cn': [f'{testusername}{i}'.encode()],
                'sn': [f'{testusername}{i}'.encode()],
            }
            conn.add(dn, attrs)


def perform_search(client, itering=False):
    if itering:
        return client.search_iter_s('dc=freeiam,dc=org', Scope.SUBTREE, '(uid=benchmark-user*)')
    return client.search_s('dc=freeiam,dc=org', Scope.SUBTREE, '(uid=benchmark-user*)')


async def perform_search_async(client, itering=False):
    if itering:
        return await client.search_iter('dc=freeiam,dc=org', Scope.SUBTREE, '(uid=benchmark-user*)')
    return await client.search('dc=freeiam,dc=org', Scope.SUBTREE, '(uid=benchmark-user*)')


def _worker_fn(client, iterations):
    for _ in range(iterations):
        perform_search(client)


async def _worker_fn_async(async_client, iterations):
    for _ in range(iterations):
        await perform_search_async(async_client)


@pytest.mark.timeout(50)
@pytest.mark.parametrize('itering', [True, False], ids=['iter', 'noiter'])
def test_sync_search(benchmark, client, itering):
    """Benchmark a single blocking LDAP search using the synchronous client."""
    benchmark(lambda: perform_search(client, itering))


@pytest.mark.timeout(50)
@pytest.mark.parametrize('itering', [True, False], ids=['iter', 'noiter'])
def test_async_search(benchmark, async_client, itering):
    """Benchmark a single asynchronous LDAP search using the async client."""
    benchmark(lambda: asyncio.run(perform_search_async(async_client, itering)))


@pytest.mark.timeout(100)
def test_parallel_sync_search(benchmark, client):
    """Benchmark N parallel synchronous LDAP searches using multiprocessing.

    Each worker performs one search call using the blocking client.

    Compares latency. Make sync and async directly comparable.
    """

    def run():
        with multiprocessing.Pool(num_workers) as pool:
            pool.map(perform_search, [client] * num_workers)

    benchmark(run)


@pytest.mark.timeout(100)
def test_parallel_async_search(benchmark, async_client):
    """Benchmark N parallel asynchronous LDAP searches using asyncio.gather().

    Each coroutine performs one search using the async client.

    Compares latency. Make sync and async directly comparable.
    """

    async def run_parallel():
        await asyncio.gather(*[perform_search_async(async_client) for _ in range(num_workers)])

    benchmark(lambda: asyncio.run(run_parallel()))


@pytest.mark.timeout(100)
def test_multiple_parallel_sync_search(benchmark, client):
    """Benchmark N parallel synchronous workers, each doing multiple searches.

    This test uses starmap and executes several sequential searches per worker.

    Maximum throughput measurement.
    """

    def run():
        with multiprocessing.Pool(num_workers) as pool:
            pool.starmap(_worker_fn, [(client, iterations_per_worker)] * num_workers)

    benchmark(run)


@pytest.mark.timeout(100)
def test_multiple_parallel_async_search(benchmark, async_client):
    """Benchmark N parallel async workers, each doing multiple searches.

    Uses asyncio.gather() with each coroutine looping independently.

    Maximum throughput measurement.
    """

    async def run_parallel():
        await asyncio.gather(*[_worker_fn_async(async_client, iterations_per_worker) for _ in range(num_workers)])

    benchmark(lambda: asyncio.run(run_parallel()))
