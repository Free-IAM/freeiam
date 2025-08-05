Authentication
==============

Authenticate using different mechanisms
---------------------------------------

.. literalinclude:: auth.py
   :language: python
   :caption: Authenticate using different mechanisms, e.g. PLAIN, EXTERNAL, SASL. OAUTHBEARER
   :start-after: start AUTH
   :end-before: start SIMPLE

SIMPLE bind operation
---------------------
.. literalinclude:: auth.py
   :language: python
   :caption: SIMPLE bind via plaintext credentials
   :start-after: start SIMPLE
   :end-before: end SIMPLE

SASL noninteractive authentication
----------------------------------
.. literalinclude:: auth.py
   :language: python
   :caption: GSSAPI (e.g. Kerberos)
   :start-after: start GSSAPI
   :end-before: end GSSAPI

OAUTHBEARER authentication
--------------------------
.. literalinclude:: auth.py
   :language: python
   :caption: OAuth 2.0 Access Token via OAUTHBEARER
   :start-after: start OAUTHBEARER
   :end-before: end OAUTHBEARER

Who am I? operation
-------------------
.. literalinclude:: auth.py
   :language: python
   :caption: Who am I?
   :start-after: start WHOAMI
   :end-before: end WHOAMI

Changing password
-----------------
.. literalinclude:: auth.py
   :language: python
   :caption: Changing password
   :start-after: start PASSWD
   :end-before: end PASSWD

EXTERNAL bind
-------------
.. literalinclude:: auth.py
   :language: python
   :caption: EXTERNAL (e.g. UNIX socket or client certificate)
   :start-after: start EXTERNAL
   :end-before: end EXTERNAL
