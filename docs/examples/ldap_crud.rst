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
The Add operation creates a new directory entry at the specified DN. The
entry must contain all attributes required by its object classes. The example
shows both a dictionary-based form and an LDAP add-list form, and handles the
case where the entry already exists.

.. literalinclude:: crud.py
   :language: python
   :caption: Create objects
   :dedent: 8
   :start-after: start CREATE
   :end-before: end CREATE

Modify
------

The Modify operation updates attributes on an existing entry. The first form
compares an old and a new attribute state, while the modification-list form
expresses individual add, delete, and replace operations. The latter is useful
when the application already knows the exact changes to apply.

.. literalinclude:: crud.py
   :language: python
   :caption: Modify objects
   :dedent: 8
   :start-after: start MODIFY
   :end-before: end MODIFY

Move, rename, modify RDN
------------------------

LDAP distinguishes changing an entry's relative distinguished name from
moving it to another parent. ``modrdn()`` changes the RDN, ``rename()`` can
apply a complete new DN, and ``move()`` changes the parent while preserving
the RDN. Changing an RDN attribute with a modify operation can also trigger an
implicit rename, depending on the server and schema.

.. literalinclude:: crud.py
   :language: python
   :caption: Move, rename, modrdn objects
   :dedent: 8
   :start-after: start MOVE
   :end-before: end MOVE

Remove
------
The Delete operation removes a single leaf entry. A non-leaf entry cannot be
deleted while it still has children; the server reports this condition as
``AllowedOnNonleaf``. Applications must remove the children first or use a
recursive operation where appropriate.

.. literalinclude:: crud.py
   :language: python
   :caption: Remove objects
   :dedent: 8
   :start-after: start REMOVE
   :end-before: end REMOVE

Remove recursive
----------------
The recursive delete helper removes an entry and all entries below it. Use it
carefully because the operation can remove an entire subtree and usually
requires elevated permissions.

.. literalinclude:: crud.py
   :language: python
   :caption: Remove objects recursive
   :dedent: 8
   :start-after: start RECURSIVE REMOVE
   :end-before: end RECURSIVE REMOVE
