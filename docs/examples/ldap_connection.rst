Establishing connections
========================

Before performing any LDAP operation, a client must establish a connection
to the server. LDAP supports different transport security models, ranging
from fully encrypted TLS sessions to unencrypted plaintext connections.
Some deployments require STARTTLS to upgrade an existing unencrypted
connection to a secure one, while others rely on direct TLS from the start.

The following examples illustrate:

* **Regular connection** — opening a standard LDAP session without additional security layers.
* **STARTTLS** — initiating an unencrypted connection, then upgrading to TLS.
* **Direct TLS** — connecting to the server using TLS from the outset.
* **Unencrypted plaintext connection** — for testing or in trusted networks only; not recommended for production.
* **Connection options** — configuring and retrieving LDAP connection parameters.

Each example assumes the server’s hostname, port, and security requirements are known.

Establish connection
--------------------
.. literalinclude:: connection.py
   :language: python
   :caption: Establish connections
   :start-after: start regular
   :end-before: end regular

Using START TLS
---------------
.. literalinclude:: connection.py
   :language: python
   :caption: Establish connections
   :start-after: start STARTTLS
   :end-before: end STARTTLS

Using TLS
---------
.. literalinclude:: connection.py
   :language: python
   :caption: Establish connections
   :start-after: start TLS
   :end-before: end TLS

Unencrypted plaintext conncetion
--------------------------------
.. literalinclude:: connection.py
   :language: python
   :caption: Establish connections
   :start-after: start plain
   :end-before: end plain

Connection options
------------------

.. literalinclude:: options.py
   :language: python
   :caption: Set and receive connection options
