import asyncio
import os
import socket
from collections import deque

import ldap
import pytest
import pytest_asyncio

from freeiam import errors
from freeiam.ldap._wrapper import _Response  # noqa: PLC2701
from freeiam.ldap.connection import Connection
from freeiam.ldap.constants import MessageId, ResponseType, RetrievalMode, Scope


@pytest_asyncio.fixture
async def conn(ldap_server, base_dn):
    """A connection to the LDAP server bound to the admin account."""
    async with Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        await conn.bind(f'cn=admin,{base_dn}', 'iamfree')
        yield conn


class FakeLDAP:
    """An LDAP socket with a deterministic result4() implementation."""

    def __init__(self):
        self.reader, self.writer = socket.socketpair()
        self.reader.setblocking(False)  # noqa: FBT003
        self._l = object()
        self.results = deque()
        self.abandoned = []
        self.reconnect_count = 0
        self.unbound = False

    def fileno(self):
        return self.reader.fileno()

    def push(self, *responses):
        self.results.extend(responses)
        self.writer.sendall(b'x' * len(responses))

    def result4(self, msgid, all, timeout, add_extop, add_ctrls):  # noqa: A002,ARG002
        assert msgid == -1  # LDAP_RES_ANY
        assert all == 0
        assert timeout == 0
        if not self.results:
            return None, None, None, [], None, None
        self.reader.recv(1)
        return self.results.popleft()

    def abandon_ext(self, msgid):
        self.abandoned.append(msgid)

    def unbind_ext(self, **kwargs):
        self.unbound = True

    def reconnect(self, *args, **kwargs):
        self.reconnect_count += 1

    def close(self):
        self.reader.close()
        self.writer.close()


@pytest.fixture
def ldap_pair():
    fake = FakeLDAP()
    conn = Connection(_conn=fake, automatic_reconnect=False)
    try:
        yield conn, fake
    finally:
        conn.disconnect()
        fake.close()


def response(kind, msgid, data=None, controls=None):
    return (kind, data, msgid, controls or [], None, None)


async def poll_all(conn, msgid):
    return [item async for item in conn._poll(conn.conn, msgid, RetrievalMode.All)]


@pytest.mark.asyncio
async def test_concurrent_requests_share_one_reader(ldap_pair):
    conn, fake = ldap_pair
    a = asyncio.create_task(poll_all(conn, 10))
    b = asyncio.create_task(poll_all(conn, 11))
    await asyncio.sleep(0)
    assert conn._reader_fd == fake.fileno()
    assert set(conn._pending) == {10, 11}

    first = [('cn=a', {'cn': [b'a']}, [])]
    second = [('cn=b', {'cn': [b'b']}, [])]
    fake.push(
        response(ldap.RES_SEARCH_ENTRY, 11, second),
        response(ldap.RES_SEARCH_ENTRY, 10, first),
        response(ldap.RES_SEARCH_RESULT, 10, [], ['ctrl-a']),
        response(ldap.RES_SEARCH_RESULT, 11, [], ['ctrl-b']),
    )
    result_a, result_b = await asyncio.wait_for(asyncio.gather(a, b), 1)
    assert result_a[0].data == first
    assert result_b[0].data == second
    assert result_a[0].ctrls == ['ctrl-a']
    assert result_b[0].ctrls == ['ctrl-b']
    assert conn._pending == {}
    assert conn._reader_fd is None


@pytest.mark.asyncio
async def test_iterative_search_keeps_reader_for_other_operation(ldap_pair):
    conn, fake = ldap_pair

    async def gather_entries():
        return [res async for res in conn._poll(fake, 1, RetrievalMode.One)]

    iter_task = asyncio.create_task(gather_entries())
    other_task = asyncio.create_task(poll_all(conn, 2))
    await asyncio.sleep(0)
    fake.push(
        response(ldap.RES_SEARCH_ENTRY, 1, [('cn=a', {}, [])]),
        response(ldap.RES_MODIFY, 2),
        response(ldap.RES_SEARCH_RESULT, 1, []),
    )
    entries, other = await asyncio.wait_for(asyncio.gather(iter_task, other_task), 1)
    assert [r.type for r in entries] == [ldap.RES_SEARCH_ENTRY, ldap.RES_SEARCH_RESULT]
    assert other[0].type == ldap.RES_MODIFY


@pytest.mark.asyncio
async def test_cancel_only_abandons_one_request(ldap_pair):
    conn, fake = ldap_pair
    a = asyncio.create_task(poll_all(conn, 10))
    b = asyncio.create_task(poll_all(conn, 11))
    await asyncio.sleep(0)
    a.cancel()
    with pytest.raises(asyncio.CancelledError):
        await a
    assert fake.abandoned == [10]
    assert conn._reader_fd == fake.fileno()
    fake.push(response(ldap.RES_MODIFY, 11))
    assert (await asyncio.wait_for(b, 1))[0].type == ldap.RES_MODIFY


@pytest.mark.asyncio
async def test_timeout_abandons_and_unregisters(ldap_pair):
    conn, fake = ldap_pair
    conn.timeout = 0.01
    with pytest.raises(TimeoutError):
        await poll_all(conn, 10)
    assert fake.abandoned == [10]
    assert conn._reader_fd is None
    assert conn._pending == {}


@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['reconnect', 'disconnect', 'unbind'])
async def test_connection_reset_wakes_all_waiters(ldap_pair, action):
    conn, fake = ldap_pair
    tasks = [asyncio.create_task(poll_all(conn, mid)) for mid in (10, 11)]
    await asyncio.sleep(0)
    if action == 'unbind':
        await conn.unbind()
        assert fake.unbound
    else:
        getattr(conn, action)()
    for task in tasks:
        with pytest.raises(RuntimeError, match='LDAP connection'):
            await asyncio.wait_for(task, 1)
    assert conn._pending == {}
    assert conn._reader_fd is None
    if action == 'reconnect':
        assert fake.reconnect_count == 1


@pytest.mark.asyncio
async def test_dispatch_failure_notifies_every_waiter(ldap_pair, monkeypatch):
    conn, fake = ldap_pair
    tasks = [asyncio.create_task(poll_all(conn, mid)) for mid in (10, 11)]
    await asyncio.sleep(0)

    def broken(*args, **kwargs):
        raise OSError('socket failed')

    monkeypatch.setattr(Connection, 'get_result', broken)
    conn._ready(fake.fileno(), fake)
    for task in tasks:
        with pytest.raises(OSError, match='socket failed'):
            await task
    assert conn._pending == {}


@pytest.mark.timeout(5)
@pytest.mark.asyncio
async def test_dispatcher_drains_buffered_responses_without_fd_readiness(monkeypatch):
    """Drain buffered responses without requiring another FD readiness event."""
    loop = asyncio.get_running_loop()
    batch_size = 64
    msgid = 123456789

    connection = Connection(automatic_reconnect=False)

    read_fd, write_fd = os.pipe()

    class FakeLDAPObject:
        @staticmethod
        def fileno():
            return read_fd

    fake_conn = FakeLDAPObject()

    responses = deque(
        _Response(
            ResponseType.SearchEntry,
            [],
            msgid,
            [],
            None,
            None,
        )
        for _ in range(batch_size + 1)
    )

    received = asyncio.Queue()
    connection._pending[msgid] = received

    processed = []
    order = []

    def get_result(self, *args, **kwargs):
        if not responses:
            return _Response(None, None, None, [], None, None)

        response = responses.popleft()
        processed.append(response)
        order.append('response')
        return response

    monkeypatch.setattr(Connection, 'get_result', get_result)

    try:
        connection._reader_fd = read_fd
        connection._reader_conn = fake_conn
        connection._reader_loop = loop

        # the pipe remains empty, so the FD is never readable
        loop.add_reader(
            read_fd,
            connection._ready,
            read_fd,
            fake_conn,
        )

        loop.call_soon(order.append, 'other_task')

        # process the first batch synchronously
        connection._ready(read_fd, fake_conn)

        assert len(processed) == batch_size
        assert received.qsize() == batch_size

        # only the scheduled call_soon() continuation can
        # process the remaining response
        async with asyncio.timeout(1):
            while len(processed) < batch_size + 1:  # noqa: ASYNC110
                await asyncio.sleep(0)

        assert len(processed) == batch_size + 1
        assert received.qsize() == batch_size + 1
        assert not responses

        # the other callback must execute between the batches
        assert order.index('other_task') < order.index(
            'response',
            batch_size,
        )

    finally:
        connection._remove_reader()
        os.close(read_fd)
        os.close(write_fd)


async def _registered_poll(conn: Connection, msgid: int) -> asyncio.Task:
    """Register a waiter on a real LDAP socket, without sending an LDAP request.

    This is a dispatcher lifecycle test, not an LDAP protocol integration test.
    The ID deliberately does not belong to an actual in-flight operation.
    """
    task = asyncio.create_task(_collect(conn, msgid))
    await asyncio.sleep(0)
    if task.done():
        await task  # surface initialization errors instead of reporting a misleading assertion
    assert msgid in conn._pending
    return task


async def _collect(conn: Connection, msgid: int):
    return [response async for response in conn._poll(conn.conn, msgid, RetrievalMode.One)]


@pytest.mark.asyncio
async def test_dispatcher_rejects_res_any(conn):
    """RES_ANY belongs to the dispatcher, never an individual waiter."""
    with pytest.raises(ValueError, match='explicit message ID'):
        await anext(conn._poll(conn.conn, MessageId.Any))
    assert not conn._pending


@pytest.mark.asyncio
async def test_dispatcher_rejects_duplicate_waiter(conn):
    """Two waiters must not compete for one response on a real connection."""
    msgid = 123456789
    task = await _registered_poll(conn, msgid)
    try:
        with pytest.raises(RuntimeError, match='already being polled'):
            await anext(conn._poll(conn.conn, msgid))
        assert msgid in conn._pending
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not conn._pending
    assert conn._reader_fd is None


@pytest.mark.asyncio
async def test_dispatcher_mismatched_remove_keeps_live_reader(conn):
    """Cleanup for a stale FD must not remove the active reader."""
    msgid = 123456790
    task = await _registered_poll(conn, msgid)
    try:
        fd = conn._reader_fd
        assert fd is not None
        conn._remove_reader(fd + 100000)
        assert conn._reader_fd == fd
        assert msgid in conn._pending
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_dispatcher_live_socket_replacement_fails_waiter(conn):
    """A second real libldap handle must not take over the active FD reader."""
    # independent live connection, never mutate the shared fixture's handle
    replacement = Connection(conn.uri, automatic_reconnect=False)
    replacement.connect()
    await replacement.bind(None, None)  # establish a real socket before inspecting fileno()
    assert replacement.fileno >= 0
    msgid = 123456791
    task = None
    try:
        task = await _registered_poll(conn, msgid)
        with pytest.raises(RuntimeError, match='LDAP socket changed'):
            conn._register_reader(replacement.conn)
        with pytest.raises(RuntimeError, match='LDAP socket changed'):
            await asyncio.wait_for(task, timeout=2)
        assert not conn._pending
        assert conn._reader_fd is None
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        # the replacement is independent and is not used by the dispatcher
        try:
            replacement.conn.unbind_s()
        finally:
            replacement.disconnect()


@pytest.mark.asyncio
async def test_dispatcher_threaded_disconnect_wakes_waiter(conn):
    """Simulate a synchronous caller disconnecting outside the event-loop thread.

    Work on a disposable, real connection to avoid disrupting other tests.
    """
    disposable = Connection(conn.uri, automatic_reconnect=False)
    disposable.connect()
    await disposable.bind(None, None)  # connect() alone may leave libldap's socket unopened
    assert disposable.fileno >= 0
    task = None
    try:
        task = await _registered_poll(disposable, 123456792)
        await asyncio.to_thread(disposable.disconnect)
        with pytest.raises(RuntimeError, match='LDAP connection closed'):
            await asyncio.wait_for(task, timeout=2)
        await asyncio.sleep(0)  # allow call_soon_threadsafe(remove_reader)
        assert not disposable._pending
        assert disposable._reader_fd is None
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        disposable.disconnect()


@pytest.mark.asyncio
async def test_dispatcher_concurrent_real_search_and_no_such_object(conn, base_dn):
    """LDAP result error for one message ID must not abort another request."""
    missing_dn = f'cn=dispatcher-missing-object,{base_dn}'

    async def missing():
        with pytest.raises(errors.NoSuchObject):
            await conn.get(missing_dn)

    async def valid():
        entries = await conn.search(str(base_dn), Scope.BASE)
        assert len(entries) == 1
        assert entries[0].dn is not None

    await asyncio.wait_for(asyncio.gather(missing(), valid()), timeout=5)
    assert not conn._pending
    assert conn._reader_fd is None


@pytest.mark.asyncio
async def test_dispatcher_real_search_iter_interleaved_with_get(conn, base_dn):
    """A real iterative search and another request share the same reader."""

    async def iterative():
        entries = []
        async for result in conn.search_iter(str(base_dn), Scope.SUBTREE, attrs=['1.1']):
            entries.append(result)
            # give the independent LDAP request an opportunity to run
            await asyncio.sleep(0)
        return entries

    async def single():
        return await conn.get(str(base_dn), attrs=['1.1'])

    entries, one = await asyncio.wait_for(asyncio.gather(iterative(), single()), timeout=10)
    assert entries
    assert one.dn is not None
    assert not conn._pending
    assert conn._reader_fd is None


def test_dispatcher_remove_reader_closed_loop(conn):
    loop = asyncio.new_event_loop()
    loop.close()

    conn._reader_loop = loop
    conn._reader_fd = 123
    conn._reader_conn = conn.conn

    conn._remove_reader()

    assert conn._reader_loop is None
    assert conn._reader_fd is None
    assert conn._reader_conn is None


class SocketProxy:
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd


@pytest.fixture
def dispatcher(conn):
    """Prepare dispatcher state using a real LDAP socket."""
    fd = conn.fileno
    assert fd >= 0
    assert not conn._pending
    assert conn._reader_fd is None

    proxy = SocketProxy(fd)
    queue = asyncio.Queue()
    msgid = 123456789

    conn._reader_fd = fd
    conn._reader_conn = proxy
    conn._reader_loop = None
    conn._pending[msgid] = queue

    yield conn, proxy, fd, msgid, queue

    conn._pending.clear()
    conn._reader_fd = None
    conn._reader_conn = None
    conn._reader_loop = None


def test_dispatcher_socket_changed_before_read(dispatcher):
    conn, proxy, fd, _msgid, queue = dispatcher

    proxy.fd = -1

    conn._ready(fd, proxy)

    exc = queue.get_nowait()
    assert isinstance(exc, RuntimeError)
    assert 'LDAP socket changed' in str(exc)
    assert not conn._pending


class InjectedLDAPError(errors.LdapError):
    def __init__(self, msgid):
        Exception.__init__(self, 'Injected LDAP error')
        self._injected_msgid = msgid

    @property
    def msgid(self):
        return self._injected_msgid


def test_dispatcher_socket_changed_during_ldap_error(dispatcher, monkeypatch):
    conn, proxy, fd, msgid, queue = dispatcher

    def get_result(*args, **kwargs):
        proxy.fd = -1
        raise InjectedLDAPError(msgid)

    monkeypatch.setattr(Connection, 'get_result', get_result)

    conn._ready(fd, proxy)

    exc = queue.get_nowait()
    assert isinstance(exc, RuntimeError)
    assert 'LDAP socket changed' in str(exc)
    assert isinstance(exc.__cause__, InjectedLDAPError)
    assert not conn._pending


def test_dispatcher_socket_changed_after_response(dispatcher, monkeypatch):
    conn, proxy, fd, msgid, queue = dispatcher

    def get_result(*args, **kwargs):
        proxy.fd = -1

        return _Response(
            ResponseType.Add,
            [],
            msgid,
            [],
            None,
            None,
        )

    monkeypatch.setattr(Connection, 'get_result', get_result)

    conn._ready(fd, proxy)

    exc = queue.get_nowait()
    assert isinstance(exc, RuntimeError)
    assert 'LDAP socket changed' in str(exc)
    assert not conn._pending


def test_dispatcher_drains_multiple_responses(dispatcher, monkeypatch):
    conn, proxy, fd, msgid, queue = dispatcher

    responses = iter([
        _Response(ResponseType.Add, [], msgid, [], None, None),
        _Response(ResponseType.Modify, [], msgid, [], None, None),
        _Response(None, None, None, [], None, None),
    ])

    calls = 0

    def get_result(*args, **kwargs):
        nonlocal calls
        calls += 1
        return next(responses)

    monkeypatch.setattr(Connection, 'get_result', get_result)

    conn._ready(fd, proxy)

    assert calls == 3
    assert queue.get_nowait().type == ResponseType.Add
    assert queue.get_nowait().type == ResponseType.Modify
    assert queue.empty()
    assert msgid in conn._pending


def test_dispatcher_batch_limit_without_pending(dispatcher, monkeypatch):
    conn, proxy, fd, msgid, _queue = dispatcher

    def get_result(*args, **kwargs):
        return _Response(
            ResponseType.SearchEntry,
            [],
            msgid,
            [],
            None,
            None,
        )

    monkeypatch.setattr(Connection, 'get_result', get_result)

    # simulate an operation that is no longer pending
    conn._pending.clear()

    conn._ready(fd, proxy)

    assert conn._drain_handle is None
    assert not conn._pending


@pytest.mark.asyncio
async def test_dispatcher_remove_reader_cancels_pending_drain(monkeypatch):
    loop = asyncio.get_running_loop()
    conn = Connection(automatic_reconnect=False)

    read_fd, write_fd = os.pipe()

    class FakeLDAPObject:
        @staticmethod
        def fileno():
            return read_fd

    fake_conn = FakeLDAPObject()

    try:
        conn._reader_loop = loop
        conn._reader_fd = read_fd
        conn._reader_conn = fake_conn

        callback_executed = False

        def continuation():
            nonlocal callback_executed
            callback_executed = True

        conn._drain_handle = loop.call_soon(continuation)
        handle = conn._drain_handle

        conn._remove_reader()

        assert handle.cancelled()
        assert conn._drain_handle is None
        assert conn._reader_loop is None
        assert conn._reader_fd is None
        assert conn._reader_conn is None

        # give the event loop an opportunity to execute callbacks
        await asyncio.sleep(0)

        assert not callback_executed

    finally:
        conn._remove_reader()
        os.close(read_fd)
        os.close(write_fd)
