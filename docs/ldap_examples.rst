TLS, STARTTLS and plain Connections
===================================

.. literalinclude:: examples/connection.py
   :language: python
   :linenos:
   :caption: Establish connections

Set and receive Connection options
==================================

.. literalinclude:: examples/options.py
   :language: python
   :linenos:
   :caption: Set and receive connection options

Authentication
==============

.. literalinclude:: examples/auth.py
   :language: python
   :linenos:
   :caption: Authenticate using different mechanisms, e.g. PLAIN, EXTERNAL, SASL. OAUTHBEARER

Synchronous API
===============

You can do everything also synchronously using the same API.

.. literalinclude:: examples/sync.py
   :language: python
   :linenos:
   :caption: The API is also available for synchronous IO blocking operations


Search and Pagination
=====================

.. literalinclude:: examples/search.py
   :language: python
   :linenos:
   :caption: Search and receive objects and attributes, optionally using pagination


CRUD operations
===============

.. literalinclude:: examples/crud.py
   :language: python
   :linenos:
   :caption: Create, Modify, Remove objects

Working with DNs and Attributes
===============================

Using LDAP Controls
===================

.. literalinclude:: examples/controls.py
   :language: python
   :linenos:
   :caption: LDAP Controls, Post-Read, Pre-Read, VLV, SSS, ...

Extended Stuff
==============

.. literalinclude:: examples/extended.py
   :language: python
   :linenos:
   :caption: Get Root DSE (Directory Server Entry), all LDAP databases, Schema or perform LDAP extended operation
