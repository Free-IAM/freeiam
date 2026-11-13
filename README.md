[![PyPI](https://img.shields.io/pypi/v/freeiam)](https://pypi.org/project/freeiam/)
[![Python](https://img.shields.io/pypi/pyversions/freeiam)](https://pypi.org/project/freeiam/)
[![CI](https://github.com/Free-IAM/freeiam/actions/workflows/ci.yml/badge.svg)](https://github.com/Free-IAM/freeiam/actions/workflows/ci.yml)
[![Docs](https://readthedocs.org/projects/free-iam/badge/?version=latest)](https://docs.freeiam.org/en/latest/)

[![Coverage](https://img.shields.io/codecov/c/github/Free-IAM/freeiam.svg)](https://codecov.io/gh/Free-IAM/freeiam)
[![pre-commit](https://github.com/Free-IAM/freeiam/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/Free-IAM/freeiam/actions/workflows/pre-commit.yml)
[![Ruff](https://img.shields.io/badge/linter-ruff-blue)](https://docs.astral.sh/ruff/)
[![mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy.readthedocs.io/)
[![ty](https://img.shields.io/badge/ty-strict-blue)](https://docs.astral.sh/ty/)

[![REUSE](https://api.reuse.software/badge/github.com/Free-IAM/freeiam)](https://api.reuse.software/info/github.com/Free-IAM/freeiam)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Free-IAM/freeiam#license)
[![Security Policy](https://img.shields.io/badge/security-policy-green)](https://github.com/Free-IAM/freeiam/security/policy)

<!--[![Issues](https://img.shields.io/github/issues/Free-IAM/freeiam.svg)](https://github.com/Free-IAM/freeiam/issues)
[![PyPI Downloads](https://img.shields.io/pypi/dm/freeiam)](https://pypistats.org/packages/freeiam) -->

# Free IAM - Free Identity and Access Management.

**Free IAM** is a flexible and open identity and access management system designed for interoperability, extensibility, and simplicity.
It provides clean APIs, powerful abstractions, and deep integration with common identity schemata and directory services.

## LDAP Client Library

FreeIAM offers both a asynchronous and synchronous LDAP client library for Python via `freeiam.ldap`, supporting the full range of client features.
For usage examples and detailed API documentation, please refer to the [official documentation](https://docs.freeiam.org/).

```python
import asyncio

from freeiam import ldap


async def main():
    async with ldap.Connection('ldap://localhost:389', timeout=30) as conn:
        # TLS
        conn.set_tls(ca_certfile='/path/to/ca.crt', require_cert=TLSVerifyMode.Hard)
        conn.start_tls()

        # authenticate
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        # search for DN and attrs
        for entry in await conn.search(search_base, Scope.Subtree, '(&(uid=*)(objectClass=person))'):
            print(entry.dn, entry.attr)

        # search iterative for DN and attrs
        async for entry in conn.search_iter(search_base, Scope.Subtree, '(&(uid=*)(objectClass=person))'):
            print(entry.dn, entry.attr)

        # search for DN
        async for entry in conn.search_dn(search_base, Scope.Subtree, '(&(uid=*)(objectClass=person))'):
            print(entry.dn)

        # search paginated via SimplePagedResult
        async for entry in conn.search_paged(
            search_base,
            Scope.Subtree,
            '(&(uid=*)(objectClass=person))',
            page_size=10,
        ):
            print(entry.dn, entry.attr, entry.page)

        # search paginated via VirtualListView + ServerSideSorting
        async for entry in conn.search_paginated(
            search_base,
            Scope.Subtree,
            '(&(uid=*)(objectClass=person))',
            page_size=10,
            sorting=[('uid', 'caseIgnoreOrderingMatch', False)],
        ):
            print(entry.dn, entry.attr, entry.page)

        # get a certain object, and use its attributes
        obj = await conn.get('uid=max.mustermann,dc=freeiam,dc=org')
        print(obj.dn, obj.attr)
        print(obj.attr['cn'])

        # get a attribute of an object
        cn = await conn.get_attr('uid=max.mustermann,dc=freeiam,dc=org', 'commonName')
        print(cn)


asyncio.run(main())
```

The same API exists synchronously:
```python
from freeiam import ldap


with ldap.Connection('ldap://localhost:389', timeout=30) as conn:
    # TLS
    conn.set_tls(ca_certfile='/path/to/ca.crt', require_cert=TLSVerifyMode.Hard)
    conn.start_tls()

    # authenticate
    conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

    # search for DN and attrs
    for entry in conn.search(search_base, Scope.Subtree, '(&(uid=*)(objectClass=person))'):
        print(entry.dn, entry.attr)
```

## Documentation

Comprehensive documentation is available to help you get started quickly and to explore advanced features.
It includes usage guides, API references, and example code snippets.

Visit the official documentation site here: [https://docs.freeiam.org/](https://docs.freeiam.org/)

## Changelog

This project follows [Semantic Versioning](https://semver.org/) to manage releases.

A detailed, human-readable changelog is maintained and can be found here: [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are very welcome!

Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started, coding standards, and the pull request process.
If you want to report bugs, request features, or discuss improvements, please open an issue on GitHub.

## License

This project is dual-licensed under the following licenses, giving fully flexibility:

- [MIT License](LICENSES/MIT.txt) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
- [Apache License 2.0](LICENSES/Apache-2.0.txt) ![License: Apache 2](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

See the LICENSES files for more details.

## Test Coverage

The project currently maintains 100% test coverage, ensuring that all code paths are exercised by automated tests.
This helps guarantee reliability, correctness, and ease of future maintenance.

## LDAP client benchmarks
The benchmark suite compares FreeIAM (`freeiam.ldap`) with Python-LDAP (`ldap`), LDAP3 (`ldap3`), and Bonsai (`bonsai`).
The connection benchmarks use a local OpenLDAP container with 20 benchmark users.

The matrix has five groups:

- `test_sync_search`: one synchronous search per benchmark call. `iter` consumes the iterator-style API; `noiter` consumes the regular API.
- `test_async_search`: one asynchronous search per benchmark call. FreeIAM and Bonsai use one persistent event loop and connection for the test. Python-LDAP uses `ldap.asyncsearch` with non-blocking result polling because its public API is otherwise synchronous.
- `test_parallel_sync_search`: four worker processes. Each worker prepares one blocking connection before measurement and uses it for the benchmark calls.
- `test_parallel_async_search`: four concurrent tasks, each using a prepared connection. This avoids sharing a connection between clients that do not support concurrent requests.
- `test_multiple_parallel_*`: four workers or tasks performing 25 searches each, for 100 searches in total.

The iterator fallback for Bonsai and LDAP3 materializes the result of their regular search because these libraries do not provide an iterator-specific API. It measures complete result handling, but it is not server-side streaming.

### Connection benchmarks
Measured on one local run with Python 3.13.5 and pytest-benchmark 5.3.1.
Values are mean/median times in microseconds per benchmark call.

<!-- benchmark-table:connection:start -->
| Backend | Sync no-iter | Sync iter | Async no-iter | Async iter | Parallel sync | Parallel async | Multiple parallel sync | Multiple parallel async |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Python-LDAP | 502.85/473.58 | 492.56/457.57 | 644.50/593.15 | 637.18/585.70 | 1524.75/1388.15 | 2088.21/1825.47 | 33980.66/32280.52 | 35671.74/35447.86 |
| FreeIAM | 637.22/606.28 | 994.07/949.06 | 1393.67/1328.45 | 1453.78/1337.97 | 1728.74/1654.69 | 5504.40/5082.83 | 37064.75/37251.53 | 136565.84/134292.38 |
| Bonsai | 730.79/694.00 | 724.56/692.79 | 1275.10/1221.13 | 1367.13/1288.54 | 1961.82/1899.58 | 5485.01/5204.34 | 43983.26/43650.35 | 128337.35/127116.84 |
| LDAP3 | 1636.98/1511.67 | 1537.30/1449.10 | - | - | 3833.96/3668.92 | - | 75988.76/75143.82 | - |
<!-- benchmark-table:connection:end -->

Python-LDAP is fastest in every directly comparable benchmark in this run. FreeIAM is closest to Python-LDAP in regular synchronous searches, while its async and parallel async paths have substantially higher overhead. LDAP3 has no async column because this benchmark suite does not provide an async adapter for it.

### Filter parser benchmarks
The filter benchmarks compare the `lark` and `libldap` parser backends through the public `Filter` API.
They cover equality, presence, substring, escaped, extensible, nested, and complex filters.
Values are mean parsing times in microseconds.

<!-- benchmark-table:filter:start -->
| Case | Lark (us) | libldap (us) |
|---|---:|---:|
| Presence | 68.94 | 80.09 |
| Equality | 76.78 | 132.94 |
| Escaped | 83.24 | 113.02 |
| Substring | 94.77 | 187.84 |
| Extensible | 99.23 | 185.41 |
| Nested | 351.07 | 425.63 |
| Complex | 837.06 | 1256.98 |
<!-- benchmark-table:filter:end -->

`lark` is faster for all cases except the nearly identical presence filter. The difference is largest for substring, extensible, and complex filters.

### DN benchmarks
The DN benchmarks cover cold-cache parsing, warm-cache parsing, normalization, normalized equality, and DN composition.
Values are mean times.

<!-- benchmark-table:dn:start -->
| Operation | Case | Mean |
|---|---|---:|
| Warm-cache parsing | User | 0.629 us |
| Warm-cache parsing | Multi-valued RDN | 0.662 us |
| Warm-cache parsing | Escaped | 0.697 us |
| Warm-cache parsing | Complex | 0.661 us |
| Cold-cache parsing | User | 3.130 us |
| Cold-cache parsing | Multi-valued RDN | 3.628 us |
| Cold-cache parsing | Escaped | 3.803 us |
| Cold-cache parsing | Complex | 3.593 us |
| Equality | Normalized multi-valued RDN | 0.999 us |
| Normalization | User | 7.062 us |
| Normalization | Multi-valued RDN | 8.366 us |
| Normalization | Escaped | 7.383 us |
| Normalization | Complex | 9.840 us |
| Composition | User DN | 9.208 us |
<!-- benchmark-table:dn:end -->

### Test system
The connection, filter, and DN runs used the following system:

| Component | Value |
|---|---|
| CPU | Intel Core i7-8565U, 4 cores / 8 threads, up to 4.6 GHz |
| Architecture | x86_64 |
| Python | CPython 3.13.5 |

The connection benchmark includes LDAP server and request/result handling overhead. Connection setup is performed before timed calls. Results from different machines, Python versions, LDAP server instances, or system loads should not be compared as absolute values.

## Project Goals
- Clean and extensible APIs and libraries
- Standards-first: implements what standards allow - no artificial limitations
- Identity and access management based on standardized object types:
  - Users
  - Groups
  - Containers
  - Organizational Units (OUs)
  - etc.
  - Authorizations
  - Roles
- Full support for widely used directory schemata:
  - POSIX
  - Kerberos
  - Samba
  - FreeIPA
  - Univention Corporate Server (UCS)
- Flexible composition of object classes (define your own object model)
- Compatibility with major LDAP servers:
  - OpenLDAP
  - 389 Directory Server
  - Samba
  - Microsoft Active Directory
- Data migration and synchronization connectors for diverse LDAP schemas
- Fully asynchronous, non-blocking I/O architecture
- HTTP API
- OAuth 2.0 SASL OAUTHBEARER bind support
- Integrated SCIM representation for modern interoperability
- Modular and configurable web UI:
  - Configurable layouts: e.g. simple, advanced, wizard-based, profile views
  - Customizable data representations and mappings
  - Unified abstractions for common directory operations
  - User-friendly and modern terminology
- Dynamic configuration via LDAP entries or static YAML files
- Maybe: Built-in event system for tracking object changes and triggers
