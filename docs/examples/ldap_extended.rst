Extended Operations
===================

LDAP **extended operations** allow clients to perform actions outside
the scope of the standard CRUD model. These are protocol extensions,
defined by unique OIDs, that enable specialized capabilities such as
password changes, schema retrieval, or custom administrative tasks.

Unlike controls, which modify existing operations, extended operations
are stand-alone requests with their own semantics and result formats.

This section shows examples of:

* Invoking extended operations by OID.
* Handling custom server responses.

Extended operations provide a flexible mechanism for implementing
advanced directory features while remaining compatible with the core
LDAP protocol.

.. literalinclude:: extended.py
   :language: python
   :caption: Perform LDAP extended operation
