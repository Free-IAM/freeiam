# CHANGELOG

<!-- version list -->

## v0.8.0 (2025-11-20)

### Bug Fixes

- **ldap.connection**: Allow passing `DN` instance to modify
  ([`6bbadb2`](https://github.com/Free-IAM/freeiam/commit/6bbadb24749184bcb06f2e2c78be9a463f668fb1))

### Documentation

- **ldap.extended_operations**: Add documentation for extended operations
  ([`8f00dc4`](https://github.com/Free-IAM/freeiam/commit/8f00dc40759377952dd274d430c95b0dd6c310dd))

### Features

- **ldap.connection**: Add convenience context manager for transactions
  ([`8c0368d`](https://github.com/Free-IAM/freeiam/commit/8c0368d47cede079637b35eedad9e051807b2147))

- **ldap.extended_operations**: Add utilities for extended operations
  ([`d352c91`](https://github.com/Free-IAM/freeiam/commit/d352c918820345939dc2b51e8b4e80a9c5136bf6))


## v0.7.0 (2025-11-14)

### Bug Fixes

- **ldap**: Fix typo in class name "Comparison"
  ([`8526c3e`](https://github.com/Free-IAM/freeiam/commit/8526c3eab9addea356c560c66fbbd89f29fc2f3e))

- **ldap.filter**: Enhance API to not give a presence match for comparision with empty strings
  ([`57436a4`](https://github.com/Free-IAM/freeiam/commit/57436a4ae31753161271c781f91a5bdbc51c5273))

- **ldap.filter**: Fix repr() of PresenceMatch to not include a empty value
  ([`0241c15`](https://github.com/Free-IAM/freeiam/commit/0241c159d0371198dc9a56b4d3bffb787d51e3e4))

### Documentation

- Add introductions to each chapter
  ([`6bc7ab6`](https://github.com/Free-IAM/freeiam/commit/6bc7ab61929154e3f362d96afbdfb85f0a0aae94))

- Fix typo "comparison"
  ([`bec78d3`](https://github.com/Free-IAM/freeiam/commit/bec78d3059702b7a43f66ece55177796b225511d))

- **ldap**: Describe extended operations
  ([`190381c`](https://github.com/Free-IAM/freeiam/commit/190381c6361410e9a1eb126de2fe040419429141))

- **ldap.dn**: Split examples into sections
  ([`dc28e9c`](https://github.com/Free-IAM/freeiam/commit/dc28e9c7cf117e6577e50e1d27de8468111cc726))

- **ldap.filter**: Enhance example about filter transformation
  ([`c5977da`](https://github.com/Free-IAM/freeiam/commit/c5977da9f10e2e9f0bc3a9881f227d224e400ed0))

### Features

- **ldap**: Add Refresh extended operation
  ([`eced9f3`](https://github.com/Free-IAM/freeiam/commit/eced9f3437349fb6d823ef88b2276504fb2ed66d))

- **ldap**: Allow setting multiple TLS settings and split TLS options into multiple enums
  ([`f7cf8ef`](https://github.com/Free-IAM/freeiam/commit/f7cf8ef7cad1c273d59b1d802dbe5898df105d81))

- **ldap.dn**: Change repr() of DN
  ([`a3c8aa2`](https://github.com/Free-IAM/freeiam/commit/a3c8aa204d4e0dd1e699e283a27f8d0bfcb391cd))


## v0.6.0 (2025-08-12)

### Documentation

- Add chapter about receiving server information
  ([`8e59b24`](https://github.com/Free-IAM/freeiam/commit/8e59b246844cc97ab976d9b16667492b97a242d9))

- **ldap.filter**: Describe LDAP filter escaping, traversing, transformation, handling,
  pretty-printing
  ([`bd3b519`](https://github.com/Free-IAM/freeiam/commit/bd3b51943d908163393ab0c423b08d4251275b34))

### Features

- **ldap**: Allow to pass uri=None to Connection, which reads LDAP URI from ldap.conf file
  ([`f3c940b`](https://github.com/Free-IAM/freeiam/commit/f3c940bab8e9474d6b3ecf41e9a702007b94327a))

- **ldap.filter**: Add `Filter` class to parse, compose, escape, unescape LDAP filters
  ([`6f45956`](https://github.com/Free-IAM/freeiam/commit/6f459564322508b43f2e5651e093b29adc2dffe7))


## v0.5.0 (2025-08-06)

### Documentation

- **examples**: Re-structure chapters into single pages
  ([`4cbecd2`](https://github.com/Free-IAM/freeiam/commit/4cbecd2ded63bf91155a9152eb29cf5aeefd4fec))

- **examples**: Split example files into sections for each use case
  ([`133e11e`](https://github.com/Free-IAM/freeiam/commit/133e11e36f11267a4bc7d0da4e9be53501e0bc7d))

- **ldap.controls**: Add example code for usage of all LDAP controls
  ([`679ec1b`](https://github.com/Free-IAM/freeiam/commit/679ec1b8c7d60c28edbfe26c916c663d3f84ada9))

### Features

- **ldap.controls**: Add support for all LDAP controls available in python-ldap
  ([`e75981e`](https://github.com/Free-IAM/freeiam/commit/e75981e3cff87819ce0950980330ccbec02aa946))


## v0.4.0 (2025-08-05)

### Documentation

- **ldap**: Document paginated search using Virtual List View and Server Side Sorting
  ([`6899609`](https://github.com/Free-IAM/freeiam/commit/6899609f8b3857420a8577923414b256b40d8f75))

### Features

- **ldap**: Add paginated search using Virtual List View and Server Side Sorting
  ([`2b3045e`](https://github.com/Free-IAM/freeiam/commit/2b3045ed8e7715797ed9b165faaf90befda0a010))

- **ldap**: Add Server Side Search and Virtual List View (SSS+VLV) control
  ([`d4cff5f`](https://github.com/Free-IAM/freeiam/commit/d4cff5f51c82fd1a3bf2633498c49b21b4187da2))


## v0.3.0 (2025-08-04)

### Documentation

- **ldap**: Add section explaning how to handle LDAP Distinguished Names correctly
  ([`eac7c4b`](https://github.com/Free-IAM/freeiam/commit/eac7c4bca6c80c1992f911ba204688eaed35e167))

### Features

- **ldap.dn**: Add `DN.compse()` method to construct DNs with automatic escaping of DN characters
  ([`8514453`](https://github.com/Free-IAM/freeiam/commit/85144538d05ea8388fad2c416eb88b9b3460c366))

- **ldap.dn**: Add more DN descriptors for common use cases
  ([`b72a12d`](https://github.com/Free-IAM/freeiam/commit/b72a12d76a5aa25bcf80eb9803f20360f04b730a))


## v0.2.0 (2025-08-03)

### Bug Fixes

- **ldap**: Handle optional `ldap.OPT_*` constants
  ([`08bdf6a`](https://github.com/Free-IAM/freeiam/commit/08bdf6ad94f93a88cba8c989a59008ac3b63a0fd))

### Features

- **ldap**: Add information about current page in paginated search results
  ([`0f9b979`](https://github.com/Free-IAM/freeiam/commit/0f9b97923d0713648f94756e8330d9a5b1b15403))

- **ldap**: Don't yield dummy result for empty search results in iterative search containing the
  response controls
  ([`07f54f2`](https://github.com/Free-IAM/freeiam/commit/07f54f2040be46a53f25e7a7d677e251bb31a588))

- **ldap**: Remove constants flagged for removal in python-ldap
  ([`d10786b`](https://github.com/Free-IAM/freeiam/commit/d10786b7898134d8b90196d7f4ae4029e3f9974e))


## v0.1.0 (2025-08-03)

### Documentation

- **ldap**: Add API docs and usage examples
  ([`dfbcbe4`](https://github.com/Free-IAM/freeiam/commit/dfbcbe40fb8ba95828e9dd095e8b88c3dff4a82c))

### Features

- **ldap**: Implement LDAP library
  ([`9413a8b`](https://github.com/Free-IAM/freeiam/commit/9413a8b8b8c339d220449aa5a7a557a0f7060a02))
