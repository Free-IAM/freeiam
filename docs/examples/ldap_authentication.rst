Authentication
==============

LDAP supports multiple authentication mechanisms, each suited to different
security requirements and deployment scenarios. This section provides working
examples for common bind operations and related authentication features.

The following examples demonstrate:

* **SIMPLE bind** - direct authentication using a plaintext username and password.
* **SASL noninteractive authentication** - e.g., using GSSAPI for Kerberos tickets.
* **OAUTHBEARER authentication** - providing an OAuth 2.0 access token for bind.
* **Who am I?** - querying the directory to determine the currently authenticated identity.
* **Changing password** - performing a password modification operation.
* **EXTERNAL bind** - authenticating via an external security layer such as a UNIX domain socket
  with peer credentials or a TLS client certificate.

Each example is self-contained and can be adapted for your environment.
They assume a connection to the LDAP server has already been established
and that appropriate credentials or tokens are available.

SIMPLE bind operation
---------------------
SIMPLE bind authenticates with a distinguished name and password. The
connection in this example is protected with TLS before the credentials are
sent. Applications should handle ``InvalidCredentials`` and avoid sending
passwords over an unencrypted connection.

.. literalinclude:: auth.py
   :language: python
   :caption: SIMPLE bind via plaintext credentials
   :start-after: start SIMPLE
   :end-before: end SIMPLE
   :dedent: 8

SASL noninteractive authentication
----------------------------------
GSSAPI performs SASL authentication using the client's Kerberos credentials,
usually from an existing ticket cache. No LDAP password is sent by the
application. The bind requires a correctly configured Kerberos realm and LDAP
service principal.

.. literalinclude:: auth.py
   :language: python
   :caption: GSSAPI (e.g. Kerberos)
   :start-after: start GSSAPI
   :end-before: end GSSAPI
   :dedent: 8

OAUTHBEARER authentication
--------------------------
OAUTHBEARER authenticates with an OAuth 2.0 access token. The LDAP server
must validate the token and map its identity to an LDAP authorization
identity. Tokens should be short-lived and must be protected like passwords.

.. literalinclude:: auth.py
   :language: python
   :caption: OAuth 2.0 Access Token via OAUTHBEARER
   :start-after: start OAUTHBEARER
   :end-before: end OAUTHBEARER
   :dedent: 8

Who am I? operation
-------------------
The ``Who Am I?`` extended operation returns the authorization identity of the
current connection. It is useful for verifying the result of a bind, in
particular when SASL authentication or authorization identity mapping is used.

.. literalinclude:: auth.py
   :language: python
   :caption: Who am I?
   :start-after: start WHOAMI
   :end-before: end WHOAMI
   :dedent: 8

Changing password
-----------------
The password modification extended operation changes a user's password
without requiring a direct modification of the ``userPassword`` attribute.
The server may require the old password, appropriate ACLs, and a configured
password policy. The example uses the currently authenticated identity.

.. literalinclude:: auth.py
   :language: python
   :caption: Changing password
   :start-after: start PASSWD
   :end-before: end PASSWD
   :dedent: 8

EXTERNAL bind
-------------
EXTERNAL authenticates through credentials established by an external
security layer. With ``ldapi:///``, the server can map the local UNIX socket's
peer credentials to an LDAP identity. The same SASL mechanism can also be
used with a client certificate when TLS client authentication is configured.

.. literalinclude:: auth.py
   :language: python
   :caption: EXTERNAL (e.g. UNIX socket or client certificate)
   :start-after: start EXTERNAL
   :end-before: end EXTERNAL
   :dedent: 4
