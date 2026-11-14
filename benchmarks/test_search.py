import asyncio
import atexit
import contextlib
import multiprocessing
import os
from collections.abc import Generator

import pytest

from freeiam import ldap
from freeiam.ldap.constants import Scope


num_workers = min(os.cpu_count() or 1, 4)
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

    async def search_iter(self, *args, **kwargs):
        """Materialize regular search results for the iterator benchmark."""
        return list(await self.search(*args, **kwargs))

    def search_s(self, *args, **kwargs):
        return self.conn.search(*args, **kwargs)

    def search_iter_s(self, *args, **kwargs):
        """Materialize regular search results for the iterator benchmark."""
        return list(self.search_s(*args, **kwargs))


class LDAPClient(Client):
    """ldap"""

    def search_s(self, *args, **kwargs):
        return self.conn.search_s(*args, **kwargs)

    def search_iter_s(self, *args, **kwargs):
        return list(ldap_search_iter_s(self.conn, *args, **kwargs))


def ldap_search_iter_s(conn, *args, **kwargs):
    import ldap as _ldap

    msgid = conn.search_ext(*args, **kwargs)
    rtype = None
    while rtype != _ldap.RES_SEARCH_RESULT:
        rtype, data, msgid, _ctrls, _name, _value = conn.result4(msgid, all=0, timeout=30)
        if rtype in {_ldap.RES_SEARCH_ENTRY, _ldap.RES_SEARCH_REFERENCE}:
            yield from data


class AsyncLDAPClient(Client):
    """Non-blocking adapter based on python-ldap's async search API."""

    async def search(self, *args, **kwargs):
        return await self._search(*args, **kwargs)

    async def search_iter(self, *args, **kwargs):
        return await self._search(*args, **kwargs)

    async def _search(self, base, scope, filter_s, attrlist=None, attrsonly=0, **kwargs):
        import ldap as _ldap
        from ldap.asyncsearch import AsyncSearchHandler

        handler = AsyncSearchHandler(self.conn)
        handler.startSearch(base, scope, filter_s, attrlist, attrsonly, **kwargs)
        results = []
        while True:
            result_type, result_list, _msgid, _ctrls = self.conn.result3(handler._msgId, 0, 0)
            if result_type is None:
                await asyncio.sleep(0)
                continue
            if result_type == _ldap.RES_SEARCH_ENTRY:
                results.extend(result_list)
            elif result_type == _ldap.RES_SEARCH_RESULT:
                return results


class LDAP3Client(Client):
    """ldap3"""

    def search_s(self, base, scope, filter_s, *args, **kwargs):
        self.conn.search(base, filter_s, 'SUBTREE' if scope == Scope.Subtree else 'BASE', *args, **kwargs)
        return self.conn.entries

    def search_iter_s(self, *args, **kwargs):
        """Materialize regular search results for the iterator benchmark."""
        return list(self.search_s(*args, **kwargs))


def client_spec(backend, ldap_server):
    return {
        'backend': backend,
        'ldap_uri': ldap_server['ldap_uri'],
        'host': ldap_server['host'],
        'port_ldap': ldap_server['port_ldap'],
        'bind_dn': ldap_server['bind_dn'],
        'bind_pw': ldap_server['bind_pw'],
    }


@contextlib.contextmanager
def sync_client(spec) -> Generator[Client, None, None]:
    """Open a synchronous client from serializable connection settings."""
    backend = spec['backend']
    if backend == 'freeiam':
        with ldap.Connection(spec['ldap_uri'], retry_delay=1, max_connection_attempts=1, timeout=15) as conn:
            conn.bind(spec['bind_dn'], spec['bind_pw'])
            yield FreeIAMClient(conn)
        return
    if backend == 'bonsai':
        import bonsai

        client = bonsai.LDAPClient(spec['ldap_uri'])
        client.set_credentials('SIMPLE', user=spec['bind_dn'], password=spec['bind_pw'])
        with client.connect() as conn:
            yield BonsaiClient(conn)
        return
    if backend == 'ldap':
        import ldap as _ldap

        conn = _ldap.initialize(spec['ldap_uri'])
        try:
            conn.simple_bind_s(spec['bind_dn'], spec['bind_pw'])
            yield LDAPClient(conn)
        finally:
            conn.unbind_s()
        return
    if backend == 'ldap3':
        from ldap3 import ALL, Connection, Server

        server = Server(spec['host'], spec['port_ldap'], use_ssl=False, get_info=ALL)
        conn = Connection(server, spec['bind_dn'], spec['bind_pw'], auto_bind=True)
        try:
            yield LDAP3Client(conn)
        finally:
            conn.unbind()
        return
    pytest.fail(f'Not Implemented: {backend}')


_sync_worker_client = None
_sync_worker_stack = None


def _close_sync_worker():
    if _sync_worker_stack is not None:
        _sync_worker_stack.close()


def _init_sync_worker(spec):
    global _sync_worker_client, _sync_worker_stack  # noqa: PLW0603
    _sync_worker_stack = contextlib.ExitStack()
    _sync_worker_client = _sync_worker_stack.enter_context(sync_client(spec))
    atexit.register(_close_sync_worker)


@pytest.fixture(params=['freeiam', 'bonsai', 'ldap', 'ldap3'])
def backend_spec(request, ldap_server):
    return client_spec(request.param, ldap_server)


@pytest.fixture
def sync_pool(backend_spec):
    """Prepare one persistent synchronous connection per worker process."""
    pool = multiprocessing.Pool(num_workers, initializer=_init_sync_worker, initargs=(backend_spec,))
    try:
        yield pool
    finally:
        pool.close()
        pool.join()


@pytest.fixture
def client(backend_spec):
    """A connection to the LDAP server bound to the admin account."""
    with sync_client(backend_spec) as connected_client:
        yield connected_client


@pytest.fixture(params=['freeiam', 'bonsai', 'ldap'])
def async_client(request, ldap_server):
    """An async client and event loop dedicated to the benchmark."""
    spec = client_spec(request.param, ldap_server)
    runner = asyncio.Runner()
    context, connected_client = runner.run(open_async_client(spec))
    try:
        yield AsyncClient(runner, context, connected_client, request.param, spec)
    finally:
        runner.run(context.__aexit__(None, None, None))
        runner.close()


@pytest.fixture
def parallel_async_client(async_client):
    """An async client with one prepared connection per concurrent worker."""
    async_client.open_parallel(num_workers)
    try:
        yield async_client
    finally:
        async_client.close_parallel()


class AsyncClient:
    """Keep an async connection and its event loop together."""

    def __init__(self, runner, context, client, backend, spec):
        self.runner = runner
        self.context = context
        self.client = client
        self.backend = backend
        self.spec = spec
        self.parallel_contexts = []
        self.parallel_clients = []

    def run(self, coroutine):
        return self.runner.run(coroutine)

    def open_parallel(self, workers):
        self.parallel_contexts, self.parallel_clients = self.runner.run(self._open_parallel(workers))

    def close_parallel(self):
        self.runner.run(self._close_parallel())
        self.parallel_contexts = []
        self.parallel_clients = []

    async def _open_parallel(self, workers):
        pairs = await asyncio.gather(*(open_async_client(self.spec) for _ in range(workers)))
        contexts, clients = zip(*pairs, strict=True)
        return list(contexts), list(clients)

    async def _close_parallel(self):
        await asyncio.gather(*(context.__aexit__(None, None, None) for context in self.parallel_contexts))


async def open_async_client(spec):
    """Open an async client and return its context manager for cleanup."""
    backend = spec['backend']
    if backend == 'freeiam':
        context = ldap.Connection(spec['ldap_uri'], retry_delay=1, max_connection_attempts=1, timeout=15)
        conn = await context.__aenter__()  # noqa: PLC2801
        await conn.bind(spec['bind_dn'], spec['bind_pw'])
        return context, FreeIAMClient(conn)
    if backend == 'bonsai':
        import bonsai

        client = bonsai.LDAPClient(spec['ldap_uri'])
        client.set_credentials('SIMPLE', user=spec['bind_dn'], password=spec['bind_pw'])
        context = client.connect(is_async=True)
        conn = await context.__aenter__()  # noqa: PLC2801
        return context, BonsaiClient(conn)
    if backend == 'ldap':
        import ldap as _ldap

        conn = _ldap.initialize(spec['ldap_uri'])
        conn.simple_bind_s(spec['bind_dn'], spec['bind_pw'])
        return _LDAPAsyncContext(conn), AsyncLDAPClient(conn)
    msg = f'Async client not implemented: {backend}'
    raise ValueError(msg)


class _LDAPAsyncContext:
    def __init__(self, conn):
        self.conn = conn

    async def __aexit__(self, etype, exc, etraceback):
        self.conn.unbind_s()


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


def _worker_fn(iterations):
    for _ in range(iterations):
        perform_search(_sync_worker_client)


def _worker_search(_worker):
    perform_search(_sync_worker_client)


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
    benchmark(lambda: async_client.run(perform_search_async(async_client.client, itering)))


@pytest.mark.timeout(100)
def test_parallel_sync_search(benchmark, sync_pool):
    """Benchmark N parallel synchronous LDAP searches using multiprocessing.

    Each worker uses a prepared blocking connection and performs one search.

    Compares latency. Make sync and async directly comparable.
    """

    def run():
        sync_pool.map(_worker_search, range(num_workers))

    benchmark(run)


@pytest.mark.timeout(100)
def test_parallel_async_search(benchmark, parallel_async_client):
    """Benchmark N parallel asynchronous LDAP searches using asyncio.gather().

    Each coroutine performs one search using its own prepared async connection.

    Compares latency. Make sync and async directly comparable.
    """

    async def run_parallel():
        await asyncio.gather(*[perform_search_async(client) for client in parallel_async_client.parallel_clients])

    benchmark(lambda: parallel_async_client.run(run_parallel()))


@pytest.mark.timeout(100)
def test_multiple_parallel_sync_search(benchmark, sync_pool):
    """Benchmark N parallel synchronous workers, each doing multiple searches.

    Each worker uses a prepared blocking connection and executes several sequential searches.

    Maximum throughput measurement.
    """

    def run():
        sync_pool.map(_worker_fn, [iterations_per_worker] * num_workers)

    benchmark(run)


@pytest.mark.timeout(100)
def test_multiple_parallel_async_search(benchmark, parallel_async_client):
    """Benchmark N parallel async workers, each doing multiple searches.

    Uses asyncio.gather() with each coroutine and its own prepared connection.

    Maximum throughput measurement.
    """

    async def run_parallel():
        await asyncio.gather(*[_worker_fn_async(client, iterations_per_worker) for client in parallel_async_client.parallel_clients])

    benchmark(lambda: parallel_async_client.run(run_parallel()))
