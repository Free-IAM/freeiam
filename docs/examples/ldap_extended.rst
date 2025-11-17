Extended Operations
===================

LDAP **extended operations** allow clients to perform actions beyond
the standard CRUD model. These are protocol extensions, defined by
unique OIDs, that enable specialized capabilities such as password
modification, Start TLS, cancellation or custom administrative tasks.

Unlike controls, which modify existing operations, extended operations
are stand-alone requests with their own semantics and result formats.

This section includes examples of:

* Invoking extended operations e.g. by OID
* Implementing custom extended operations

Extended operations provide a flexible mechanism for implementing
advanced directory features while remaining compatible with the core
LDAP protocol.

Who Am I?
---------

The *Who Am I?* extended operation is built into most clients and
available directly as a method of the connection.

.. literalinclude:: extended.py
   :language: python
   :start-after: start WHOAMI
   :end-before: END WHOAMI
   :caption: Using the Who Am I? extended operation

Automatic object removal (refresh Time to Live (TTL))
-----------------------------------------------------

Dynamic LDAP entries are automatically removed when their configured time-to-live (TTL) expires.
To prevent expiration, these entries must be periodically refreshed.
The refresh extended operation resets the TTL (specified in seconds),
effectively extending the entry's lifetime until the next refresh.


.. literalinclude:: extended.py
   :language: python
   :start-after: start REFRESH
   :end-before: END REFRESH
   :caption: Refreshing the TTL of a dynamic entry

Transactions
------------

Some directory servers support transactional updates. Transactions
allow multiple modifications to be applied atomically. Extended
operations are used to start, commit, or abort transactions.

.. literalinclude:: extended.py
   :language: python
   :start-after: start TRANSACTION
   :end-before: end TRANSACTION
   :caption: Executing a transactional update

This can also be achieved with a context manager:

.. literalinclude:: extended.py
   :language: python
   :start-after: start CONTEXT TRANSACTION
   :end-before: end CONTEXT TRANSACTION
   :caption: Executing a transactional update

Sync Replication
----------------

Certain replication mechanisms, such as ``SyncRepl``, rely on extended
operations to maintain replication state or retrieve changes. Clients
can use these operations to participate in replication or query
replication metadata.

.. literalinclude:: extended.py
   :language: python
   :start-after: start SYNCREPL
   :end-before: end SYNCREPL
   :caption: Using extended operations for SyncRepl replication

Perform extended operations by OID
----------------------------------

Extended operations are always identified by a unique OID.
They may be standard, vendor-specific, or custom, and can be
invoked using existing request and response implementations or by providing custom implementations when needed.

.. literalinclude:: extended.py
   :language: python
   :start-after: start EXTENDED
   :end-before: end EXTENDED
   :caption: Performing a custom LDAP extended operation by OID
