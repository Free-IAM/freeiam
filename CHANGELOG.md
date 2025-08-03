# CHANGELOG

<!-- version list -->

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
