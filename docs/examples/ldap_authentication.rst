Authentication
==============

LDAP supports multiple authentication mechanisms, each suited to different
security requirements and deployment scenarios. This section provides working
examples for common bind operations and related authentication features.

The following examples demonstrate:

* **SIMPLE bind** — direct authentication using a plaintext username and password.
* **SASL noninteractive authentication** — e.g., using GSSAPI for Kerberos tickets.
* **OAUTHBEARER authentication** — providing an OAuth 2.0 access token for bind.
* **Who am I?** — querying the directory to determine the currently authenticated identity.
* **Changing password** — performing a password modification operation.
* **EXTERNAL bind** — authenticating via an external security layer such as a UNIX domain socket
  with peer credentials or a TLS client certificate.

Each example is self-contained and can be adapted for your environment.
They assume a connection to the LDAP server has already been established
and that appropriate credentials or tokens are available.

SIMPLE bind operation
---------------------
.. literalinclude:: auth.py
   :language: python
   :caption: SIMPLE bind via plaintext credentials
   :start-after: start SIMPLE
   :end-before: end SIMPLE
   :dedent: 8

SASL noninteractive authentication
----------------------------------
.. literalinclude:: auth.py
   :language: python
   :caption: GSSAPI (e.g. Kerberos)
   :start-after: start GSSAPI
   :end-before: end GSSAPI
   :dedent: 8

OAUTHBEARER authentication
--------------------------
.. literalinclude:: auth.py
   :language: python
   :caption: OAuth 2.0 Access Token via OAUTHBEARER
   :start-after: start OAUTHBEARER
   :end-before: end OAUTHBEARER
   :dedent: 8

Who am I? operation
-------------------
.. literalinclude:: auth.py
   :language: python
   :caption: Who am I?
   :start-after: start WHOAMI
   :end-before: end WHOAMI
   :dedent: 8

Changing password
-----------------
.. literalinclude:: auth.py
   :language: python
   :caption: Changing password
   :start-after: start PASSWD
   :end-before: end PASSWD
   :dedent: 8

EXTERNAL bind
-------------
.. literalinclude:: auth.py
   :language: python
   :caption: EXTERNAL (e.g. UNIX socket or client certificate)
   :start-after: start EXTERNAL
   :end-before: end EXTERNAL
   :dedent: 4
