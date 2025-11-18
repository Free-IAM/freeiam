#!/bin/sh
# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
# copy the async class and transform into synchronous execution

expr="
/from freeiam.ldap.sync_connection import/d;
/_futures:/d;
/self._remove_reader()/d;
/^ *async def _poll(/,\$d;
s/def _poll_s/def _poll/g;

s/await //g;
s/asyncio.sleep/time.sleep/g;
s/loop = asyncio.get_running_loop()//g;
s/loop.run_in_executor(None, functools.partial(func, \*args, \*\*kwargs))/func(*args, **kwargs)/g;
s/import asyncio/import time/g;
s/async def /def /g;
s/async for /for /g;
s/async with /with /g;
s/anext(/next(/g;
s/asynccontextmanager/contextmanager/g;
s/StopAsyncIteration/StopIteration/g;
/^ *def __enter__(/,/^$/d
/^ *def __exit__(/,/^$/d
s/def __aenter__/def __enter__/g;
s/def __aexit__/def __exit__/g;
s/self\.__conn_s\./self./g;
/^[[:space:]]*@property[[:space:]]*$/{
N
/^[[:space:]]*@property[[:space:]]*\n[[:space:]]*def _sync_connection(self):[[:space:]]*$/s/.*\n//
}
/^ *def _sync_connection(/,/^$/d
s/self\._sync_connection\./self./g;
"
expr_py="
s/pytest_asyncio/pytest/g;
s/^@pytest.mark.asyncio$//g;
s/\.aclose(/.close(/g;
s/ldap.Connection/ldap.connection.SynchronousConnection/g;
s/TESTUSERNAME = 'testuser'/TESTUSERNAME = 'testsynuser'/g
s/PAGEPREFIX = 'page'/PAGEPREFIX = 'synpage'/g;
"
#/^ *async def _execute(/,\$d;
# s/def _execute_iter_s/def _execute_iter/g;
# s/def _execute_s/def _execute/g;
sed "$expr" src/freeiam/ldap/connection.py > src/freeiam/ldap/sync_connection.py
ruff format src/freeiam/ldap/sync_connection.py
ruff check --add-noqa --select SIM113 src/freeiam/ldap/sync_connection.py
ruff check --fix --unsafe-fixes --select I001,F401,UP028,C416 src/freeiam/ldap/sync_connection.py

sed "${expr}${expr_py}" tests/test_ldap_connection.py > tests/test_ldap_connection_sync.py
ruff format tests/test_ldap_connection_sync.py
ruff check --add-noqa --select SIM113,SIM117 tests/test_ldap_connection_sync.py
ruff check --fix --unsafe-fixes --select I001,PT,C416,SIM117 tests/test_ldap_connection_sync.py
