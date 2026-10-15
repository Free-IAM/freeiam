Establishing connections
========================

Before performing any LDAP operation, a client must establish a connection
to the server. LDAP supports different transport security models, ranging
from fully encrypted TLS sessions to unencrypted plaintext connections.
Some deployments require STARTTLS to upgrade an existing unencrypted
connection to a secure one, while others rely on direct TLS from the start.

The following examples illustrate:

* **Regular connection** - opening a standard LDAP session without additional security layers.
* **STARTTLS** - initiating an unencrypted connection, then upgrading to TLS.
* **Direct TLS** - connecting to the server using TLS from the outset.
* **Unencrypted plaintext connection** - for testing or in trusted networks only; not recommended for production.
* **Connection options** - configuring and retrieving LDAP connection parameters.

Each example assumes the server’s hostname, port, and security requirements are known.

Establish connection
--------------------
The regular connection example shows the complete connection lifecycle:
connect, bind, reconnect, unbind, and disconnect. A context manager is usually
preferable because it closes the connection automatically when leaving the
block.

.. literalinclude:: connection.py
   :language: python
   :caption: Ways of establishing connections
   :start-after: start regular
   :end-before: end regular

Using START TLS
---------------
STARTTLS begins as a plaintext LDAP connection and upgrades that same session
to TLS before authentication. Certificate verification should be enabled in
production by using an appropriate CA certificate and a strict verification
mode.

.. literalinclude:: connection.py
   :language: python
   :caption: Establish connection using START TLS
   :start-after: start STARTTLS
   :end-before: end STARTTLS

Using TLS
---------
Direct TLS establishes encryption during the initial connection, before any
LDAP protocol exchange or bind credentials are sent. The LDAP server must
provide a TLS listener, commonly on port 636.

.. literalinclude:: connection.py
   :language: python
   :caption: Establish connection using TLS
   :start-after: start TLS
   :end-before: end TLS

Unencrypted plaintext connection
--------------------------------
An unencrypted connection sends LDAP traffic, including simple-bind
credentials, without transport protection. It can be useful for local tests
or trusted development networks, but should not be used in production.

.. literalinclude:: connection.py
   :language: python
   :caption: Establish insecure plaintext connection
   :start-after: start plain
   :end-before: end plain

Connection options
------------------

Connection options control transport and protocol behavior such as referrals,
timeouts, TLS verification, and automatic reconnects. Options can be set and
read through the connection object before or after connecting, depending on
the option.

.. literalinclude:: options.py
   :language: python
   :caption: Set and receive connection options
