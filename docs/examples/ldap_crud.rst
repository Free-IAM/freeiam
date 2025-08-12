CRUD (Create, Update, Delete)
=============================

LDAP directories support the standard set of data modification
operations, often referred to as **CRUD**: Create, Read, Update, and
Delete. While reading entries is handled through searches (see
:ref:`search-examples`), this section focuses on the operations that
change directory content.

The examples below demonstrate:

* **Create** -- adding new entries to the directory with defined
  attributes.
* **Modify** -- updating attributes of existing entries.
* **Move, rename, or change the RDN** -- altering an entry's position or
  name within the directory tree.
* **Remove** -- deleting entries.
* **Recursive removal** -- deleting an entry along with all its
  subentries in one operation.

These operations can be combined to maintain and restructure directory
data, whether you are provisioning new users, updating existing
information, or cleaning up obsolete entries.

Create
------
.. literalinclude:: crud.py
   :language: python
   :caption: Create objects
   :dedent: 8
   :start-after: start CREATE
   :end-before: end CREATE

Modify
------

.. literalinclude:: crud.py
   :language: python
   :caption: Modify objects
   :dedent: 8
   :start-after: start MODIFY
   :end-before: end MODIFY

Move, rename, modify RDN
------------------------

.. literalinclude:: crud.py
   :language: python
   :caption: Move, rename, modrdn objects
   :dedent: 8
   :start-after: start MOVE
   :end-before: end MOVE

Remove
------
.. literalinclude:: crud.py
   :language: python
   :caption: Remove objects
   :dedent: 8
   :start-after: start REMOVE
   :end-before: end REMOVE

Remove recursive
----------------
.. literalinclude:: crud.py
   :language: python
   :caption: Remove objects recursive
   :dedent: 8
   :start-after: start RECURSIVE REMOVE
   :end-before: end RECURSIVE REMOVE
