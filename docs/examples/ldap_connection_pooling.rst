Connection pooling
==================

Establishing an LDAP connection can be expensive, particularly when TCP, TLS,
and authentication handshakes are required. Applications handling many short
requests may therefore benefit from reusing established connections instead of
creating a new connection for every operation.

However, LDAP connection pooling requires careful consideration. An LDAP
connection is not merely a stateless transport channel: some operations change
the state of the connection, while others depend on state established by
previous requests. Reusing a connection without accounting for that state may
produce unexpected results or even security problems.

Connection-bound state
----------------------

Not all LDAP operations can safely be distributed across arbitrary connections.
Examples include:

* **Bind operations** change the authentication and authorization identity of
  the LDAP session. A subsequent operation on that connection may execute
  with different privileges than expected.
* **Simple Paged Results** use a server-provided cookie to continue a search.
  The cookie is opaque and should not be assumed to work on a different
  connection or backend server.
* **Virtual List View (VLV)** and server-side sorting may depend on a stable
  result set or server-maintained context. Continuation requests may need to
  reach the same backend, subject to server-specific behavior.
* **LDAP transactions**, where supported, associate a sequence of operations
  with transaction state. Requests belonging to a transaction must follow the
  protocol's connection and transaction requirements.
* **Outstanding asynchronous requests** may still have responses pending on
  the connection. Returning it to a pool before those responses are handled
  can cause the next borrower to receive unexpected messages.

.. note::

   LDAP controls are not necessarily stateful. Whether an operation requires
   connection affinity depends on the control, the server implementation,
   and potentially the load balancer in front of the server.

Authentication and connection reuse
-----------------------------------

A pool may maintain connections bound as a service account for directory
searches. Applications sometimes reuse such connections to verify user
credentials by performing another Bind.

For example:

1. Borrow a connection authenticated as a service account.
2. Bind as the user to verify the supplied credentials.
3. Return the connection to the pool.
4. Another request borrows the same connection and performs a search.

Unless the connection was restored to its expected authentication state,
the final search may run under the user's identity rather than the service
account's identity. This can cause authorization failures or unintended
access to directory data.

.. warning::

   A Bind is not an isolated password-check operation. It changes the
   authentication state of the LDAP connection. A failed Bind must not be
   treated as preserving the previous authenticated identity.

A pool that permits callers to Bind must have a defined policy for returning
connections. Depending on the application, it may rebind using the service
credentials, discard the connection and create another, or keep connections
with different identities in separate pools. A failed attempt to restore the
required state must never result in that connection being handed out as clean.

Replication and read-after-write consistency
--------------------------------------------

LDAP deployments often contain multiple directory servers or replicas behind
a load balancer. Changes may be replicated asynchronously, and connections
in the same pool may reach different backend servers.

Consider the following sequence:

1. Connection A adds a new LDAP entry on server A.
2. The application releases connection A.
3. Connection B searches for the new entry on server B.
4. Server B has not yet received the replicated change.

The search may return no result even though the write succeeded.

Reusing the **same** client connection does not always guarantee consistency,
either: proxies may route operations independently, and some deployments use
separate writable and read-only endpoints. Where read-after-write consistency
is required, the application must understand server routing, replication,
and the consistency guarantees of the directory service.

Connection ownership and concurrency
------------------------------------

A pool must define how connections are borrowed and returned. For synchronous
applications, exclusive ownership is often the simplest model: one caller
uses a connection until it has finished its related operations.

A context manager can make this lifetime explicit:

.. code-block:: python

   # Conceptual example, not a FreeIAM pooling API.
   with pool.acquire() as conn:
       # Related operations remain on the borrowed connection.
       results = conn.search(...)
       process(results)

The connection should be released even if an operation raises an exception.
Without a context manager, equivalent cleanup belongs in a ``finally`` block.

.. warning::

   Returning a connection to the pool while another thread or task is still
   using it may mix responses or authentication state between unrelated
   requests. Pool bookkeeping locks do not, by themselves, make concurrent
   operations on the same connection safe.

Asynchronous LDAP clients can potentially multiplex requests using message
identifiers, but sharing a connection still requires explicit coordination of
responses, Bind operations, connection-wide state, and cancellation. This is a
separate design decision from reusing idle connections.

Connection lifecycle
--------------------

Keeping connections open reduces repeated setup costs, but introduces lifecycle
management requirements:

* **Minimum and maximum size:** prewarming connections can reduce latency,
  while an upper bound prevents unbounded resource usage.
* **Borrowing policy:** when all connections are busy, callers may wait,
  fail, or open another connection within the configured limit.
* **Health checks:** an idle connection may have been closed by the server,
  firewall, or load balancer. A successful check does not eliminate the
  possibility of failure on the next operation.
* **State cleanup:** a returned connection must not retain an unexpected
  authentication identity, unfinished operations, or other session state.
* **Timeouts and cancellation:** interrupted operations must not leave an
  unusable connection available for reuse.
* **Shutdown:** applications must close pooled connections deliberately to
  release local and server-side resources.

Different applications may require different policies. Short web requests may
benefit from a bounded pool of reusable service-account connections, whereas
batch operations or stateful LDAP workflows may need long-lived exclusive
connections. Asynchronous applications may use a different ownership model.

.. note::

   A connection pool improves connection reuse, not LDAP protocol semantics.
   Before introducing one, establish which operations need connection
   affinity, which state may change, and how a connection is made safe for
   the next borrower.
