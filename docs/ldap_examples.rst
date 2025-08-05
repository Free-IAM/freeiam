
Connection initialization (TLS, STARTTLS)
=========================================

.. literalinclude:: examples/connection.py
   :language: python
   :linenos:
   :caption: Establish connections

Connection options
==================

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

.. _search-examples:

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

Distinguished Name (DN) Handling
================================

An LDAP Distinguished Name (DN) consists of zero, one, or multiple relative distinguished names (RDNs), and serves as the unique identifier for an object in the LDAP directory.

For example, ``uid=max.mustermann,ou=Developers,dc=freeiam,dc=org`` is the fully distinguished name of a user object.
It represents the position of the object in the LDAP tree, with the hierarchy proceeding from right to left.

The trailing RDNs (e.g., ``dc=freeiam,dc=org``) typically form the base DN, also known as the naming context or root object of the directory.
Note that the directory might not contain an actual object entry for each component (e.g., ``dc=org`` may not exist as a separate object).

Each RDN usually consists of a single Attribute Value Assertion (AVA), such as ``uid=max``.
In some cases, multiple AVAs can be combined to form a multi-valued RDN, for example: ``uid=max + sn=Mustermann``.

Working with LDAP DNs in applications is not always straightforward. There are several important considerations:

1. **Escaping special characters**

   Values derived from user input must be properly escaped, similar to how URL components are encoded.
   Special characters such as ``+``, ``=``, ``,``, ``\\``, ``#``, ``;``, ``"``, ``<``, and ``>`` must be escaped.
   When parsing a DN, these escape sequences must be correctly handled, which rules out naïve string splitting or regular expression matching.
   Instead, parsing requires a proper state machine.

   Escaping is typically done by prefixing the character with a backslash, or by using a hexadecimal escape sequence.  
   Examples: ``cn=Mustermann\,Max``, ``cn=Mustermann\2CMax``.

   Alternatively, the entire attribute value can be enclosed in double quotes: ``cn="Mustermann,Max"``.
   Within quoted values, only the backslash and the quote character itself must be escaped.


2. **Canonical equivalence and normalization**

   LDAP DNs can be written in multiple equivalent forms, which means string comparisons must not be done directly.
   For example, ``uid = Administrator`` is equivalent to ``uid=Administrator``. Proper **DN normalization** is required to compare DNs correctly.

3. **Case sensitivity**

   DNs are not universally case-insensitive.
   Whether an RDN value is case-insensitive depends on the attribute's syntax and matching rules as defined in the LDAP schema.
   For example, ``dc=FreeIAM`` is considered equal to ``dc=freeiam``, while ``memberUid=alice`` is **not** equal to ``memberUid=Alice``.  
   However, **attribute names** themselves are always case-insensitive, so ``DC=freeiam`` equals ``dc=freeiam``.

   Server implementations may handle this differently in practice. For bind operations, DNs are generally treated in a case-insensitive way.

4. **Attribute aliases and OIDs**

   LDAP attributes may have aliases. For example, ``cn=foo`` is equivalent to ``commonName=foo``.
   It's also valid to specify attribute types using their object identifier (OID), making the DN ``2.5.4.3=foo`` also equivalent.

5. **Attribute-specific constraints**

   Certain attributes have restrictions on allowed values.
   For example, the ``c`` (countryName) attribute must be a two-letter country code, making ``c=FOO`` invalid.

6. **Different DN representations**

   LDAP Distinguished Names can be expressed in multiple notations.
   While LDAPv3 string representation is the standard, several alternative formats exist.
   These are mostly used for display or integration purposes and are **not interchangeable** without proper conversion:

   - **LDAPv3 format** (standard):  
     ``uid=max.mustermann,ou=Developers,dc=freeiam,dc=org``  
     This is the formal string representation used in protocols and schemas.

   - **User-Friendly Name (UFN)** (deprecated):  
     ``max.mustermann, Developers, freeiam.org``  
     A more human-readable form, not standardized in modern LDAP.

   - **DCE format** (Directory Cell Name / X.500 style):  
     ``/.../org/freeiam/Developers/max.mustermann``  
     Common in older X.500 or DCE environments.

   - **AD Canonical Name format** (used in Microsoft Active Directory):  
     ``freeiam.org/Developers/max.mustermann``  
     Often seen in UI contexts (e.g., PowerShell, admin consoles), but not a valid DN in protocol operations.

   - **URL notation** (LDAP URLs):  
     ``ldap://ldap.freeiam.org/uid=max.mustermann,ou=Developers,dc=freeiam,dc=org``  
     Used to specify DNs as part of a full LDAP URL, including host and options.

   Applications must normalize and convert these forms to proper LDAPv3 syntax before using them in directory operations.

7. **UTF-8 encoding**

   At least all LDAP DNs must be valid UTF-8 encoded strings :-).

Due to these many nuances, DNs should never be manually parsed, compared, or interpreted in security-sensitive contexts.
Always let the LDAP server handle DN logic and comparisons.

FreeIAM provides the following mechanisms to safely and reliably work with LDAP DNs:

.. literalinclude:: examples/dn.py
   :language: python
   :linenos:
   :caption: LDAP DN handling

Using LDAP Controls
===================

LDAP operations can be extended using LDAP controls, which provide additional features and behaviors.

Controls can be passed explicitly with each operation, or applied globally to all operations via the connection object, as shown below:

.. literalinclude:: examples/controls.py
   :language: python
   :start-after: use connection wide control
   :end-before: end use connection wide control

The following example shows how to import the available controls:

.. literalinclude:: examples/controls.py
   :language: python
   :caption: Importing LDAP server controls
   :start-after: control imports
   :end-before: end control imports

Simple Paged Results, Virtual List View, and Server-Side Sorting Controls
-------------------------------------------------------------------------

The ``SimplePagedResultsControl``, ``VirtualListViewControl``, and ``ServerSideSortingControl`` are integrated into the ``search()``, ``search_paged()``, and ``search_paginated()`` methods.

Refer to the :ref:`search-examples` for practical usage.

PreRead and PostRead Controls
-----------------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: PostRead Control
   :start-after: use PostRead Control
   :end-before: end use PostRead Control

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: PreRead Control
   :start-after: use PreRead Control
   :end-before: end use PreRead Control

Assertion Control
-----------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: Assertion Control
   :start-after: use Assertion Control
   :end-before: end use Assertion Control


RelaxRules Control
------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: RelaxRules Control
   :start-after: use RelaxRules Control
   :end-before: end use RelaxRules Control


Proxy Authorization Control
----------------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: ProxyAuthz Control
   :start-after: use ProxyAuthz Control
   :end-before: end use ProxyAuthz Control


MatchedValues Control
---------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: MatchedValues Control
   :start-after: use MatchedValues Control
   :end-before: end use MatchedValues Control


PersistentSearch Control
------------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: PersistentSearch Control (not supported by OpenLDAP)
   :start-after: use PersistentSearch Control
   :end-before: end use PersistentSearch Control


SessionTracking Control
-----------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: SessionTracking Control (not supported by OpenLDAP)
   :start-after: use SessionTrackingControl
   :end-before: end use SessionTrackingControl


GetEffectiveRights Control
--------------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: GetEffectiveRights Control
   :start-after: use GetEffectiveRights Control
   :end-before: end use GetEffectiveRights Control


Authorization Identity Control
------------------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: Authorization Identity Control
   :start-after: use Authorization Identity Control
   :end-before: end use Authorization Identity Control


Dereference Control
-------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: Dereference Control (not supported by OpenLDAP)
   :start-after: use Dereference Control
   :end-before: end use Dereference Control


Manage DSA Information Tree Control
-------------------

.. literalinclude:: examples/controls.py
   :language: python
   :dedent: 4
   :caption: ManageDSAIT Control
   :start-after: use ManageDSAITControl
   :end-before: end use ManageDSAITControl


Extended Stuff
==============

.. literalinclude:: examples/extended.py
   :language: python
   :linenos:
   :caption: Get Root DSE (Directory Server Entry), all LDAP databases, Schema or perform LDAP extended operation
