[![CI](https://github.com/Free-IAM/freeiam/actions/workflows/ci.yml/badge.svg)](https://github.com/Free-IAM/freeiam/actions/workflows/ci.yml)
[![pre-commit](https://github.com/Free-IAM/freeiam/actions/workflows/pre-commit.yml/badge.svg)](https://github.com/Free-IAM/freeiam/actions/workflows/pre-commit.yml)
[![Coverage](https://img.shields.io/codecov/c/github/Free-IAM/freeiam.svg)](https://codecov.io/gh/Free-IAM/freeiam)

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Docs](https://readthedocs.org/projects/free-iam/badge/?version=latest)](https://docs.freeiam.org/en/latest/)
[![Ruff](https://img.shields.io/badge/linter-ruff-blue)](https://docs.astral.sh/ruff/)

[![PyPI](https://img.shields.io/pypi/v/freeiam)](https://pypi.org/project/freeiam/)
[![Issues](https://img.shields.io/github/issues/Free-IAM/freeiam.svg)](https://github.com/Free-IAM/freeiam/issues)
[![Security Policy](https://img.shields.io/badge/security-policy-green)](https://github.com/Free-IAM/freeiam/security/policy)
[![REUSE status](https://api.reuse.software/badge/github.com/Free-IAM/freeiam)](https://api.reuse.software/info/github.com/Free-IAM/freeiam)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

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
        conn.set_tls(ca_certfile='/path/to/ca.crt', require_cert=TLSOptionValue.Hard)
        await conn.start_tls()

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

        # search paginated
        async for entry in conn.search_paginated(
            search_base,
            Scope.Subtree,
            '(&(uid=*)(objectClass=person))',
            page_size=10,
        ):
            print(entry.dn, entry.attr)

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
    conn.set_tls(ca_certfile='/path/to/ca.crt', require_cert=TLSOptionValue.Hard)
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
Current benchmarks indicate that the synchronous non-iterable methods offer the best performance.
The benchmark suite compares FreeIAM (`freeiam.ldap`) against Python-LDAP (`ldap`), LDAP3 (`ldap3`), and Bonsai (`bonsai`).

Please note this is a work in progress (WIP) and the benchmark coverage and accuracy will be improved over time.

| Testname                            | Min (us)  | Max (us)   | Mean (us) | StdDev (us) | Median (us) | IQR (us) | Outliers | OPS      | Rounds | Iterations |
|-----------------------------------|-----------|------------|-----------|-------------|-------------|----------|----------|----------|--------|------------|
| test_sync_search[ldap-noiter]      | 336.42    | 1762.35    | 466.35    | 132.87      | 428.97      | 103.48   | 120;76   | 2144.33  | 1418   | 1          |
| test_sync_search[freeiam-noiter]   | 381.79    | 1425.61    | 572.07    | 118.68      | 545.87      | 109.69   | 165;51   | 1748.04  | 1143   | 1          |
| test_sync_search[bonsai-noiter]    | 446.28    | 1514.67    | 680.02    | 138.66      | 645.65      | 111.18   | 113;55   | 1470.55  | 861    | 1          |
| test_sync_search[freeiam-iter]     | 692.62    | 2134.28    | 958.01    | 186.67      | 913.93      | 169.14   | 72;29    | 1043.83  | 488    | 1          |
| test_sync_search[ldap3-noiter]     | 1181.49   | 3948.65    | 1603.93   | 333.01      | 1518.64     | 253.67   | 71;43    | 623.47   | 482    | 1          |
| test_async_search[freeiam-noiter]  | 1577.63   | 6493.86    | 2659.18   | 634.62      | 2430.03     | 676.09   | 58;22    | 376.06   | 328    | 1          |
| test_async_search[freeiam-iter]    | 2768.34   | 5792.08    | 3479.36   | 598.57      | 3279.16     | 579.05   | 34;11    | 287.41   | 169    | 1          |
| test_parallel_sync_search[freeiam] | 12317.69  | 46028.09   | 14145.28  | 4472.71     | 13232.57    | 972.18   | 1;4      | 70.70    | 55     | 1          |
| test_multiple_parallel_sync_search[freeiam] | 33453.03  | 39019.64   | 35980.09  | 1332.03     | 36083.70    | 1862.24  | 10;0     | 27.79    | 28     | 1          |

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
