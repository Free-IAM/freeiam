Synchronous API
===============

In addition to the asynchronous interface, the same LDAP client API can be
used in a synchronous (blocking) manner. This is useful for scripts,
utilities, or environments where asynchronous execution is not required
or where blocking I/O is acceptable.

The synchronous API mirrors the asynchronous one, allowing you to reuse
the same method calls and code structure without modification -- only the
event loop integration changes.

The following example demonstrates how to perform the same operations
using synchronous calls.

.. literalinclude:: sync.py
   :language: python
   :caption: The API is also available for synchronous IO blocking operations
