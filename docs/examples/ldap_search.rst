Search and pagination
=====================
.. _search-examples:

Searching is one of the most common LDAP operations. It allows clients
to retrieve directory entries matching specific criteria, optionally
returning only selected attributes. This section demonstrates a variety
of search techniques and server-side features for controlling result
sets.

The examples below cover:

* **Basic searches** -- retrieving entries and attributes within a
  specified subtree or scope.
* **Iterative searches** -- streaming results as they arrive.
* **Counting** -- counting matching entries without returning them.
* **Specialized searches** -- retrieving only the distinguished names,
  single attributes, or asserting result uniqueness.
* **Pagination** -- splitting large result sets into manageable chunks
  using either the Simple Paged Results control or the Virtual List View
  control.
* **Sorting** -- requesting server-side ordering of results.
* **Existence checks** -- quickly verifying whether an entry exists.
* **Error handling** -- dealing with missing search bases or other
  exceptional conditions.

These techniques can be combined to efficiently retrieve exactly the
data you need from large or complex directory structures.

Search and receive objects and attributes
-----------------------------------------

The regular search returns matching entries with their distinguished names and
requested attributes. ``Scope.SUBTREE`` searches the complete subtree below
the base DN, while the LDAP filter limits which entries are returned.

.. literalinclude:: search.py
   :language: python
   :caption: subtree search
   :dedent: 8
   :start-after: start SEARCH
   :end-before: end SEARCH

Search iterative
----------------
The iterative search yields entries as the server returns them instead of
collecting the complete result set first. This reduces memory usage and lets
the application start processing large searches immediately.

.. literalinclude:: search.py
   :language: python
   :caption: iterative search
   :dedent: 8
   :start-after: start ITERSEARCH
   :end-before: end ITERSEARCH

Search for DN only
------------------
When an application only needs to identify matching entries, a DN-only search
avoids transferring regular attributes. This is useful for membership checks,
bulk processing, and follow-up operations.

.. literalinclude:: search.py
   :language: python
   :caption: search for DN
   :dedent: 8
   :start-after: start DNSEARCH
   :end-before: end DNSEARCH

Paginated search using SimplePagedResult
----------------------------------------
Simple Paged Results divides a large result set into fixed-size pages. The
client and server exchange a cookie between pages, allowing the application
to process bounded batches without loading all entries at once.

.. literalinclude:: search.py
   :language: python
   :caption: simple paginated search
   :dedent: 8
   :start-after: start PAGEDSEARCH
   :end-before: end PAGEDSEARCH

Server-Side Sort search
-----------------------
Server-side sorting asks the directory server to order matching entries by
the specified attribute and matching rule. Sorting is performed before the
results are returned and is useful when the client needs stable ordering.

.. literalinclude:: search.py
   :language: python
   :caption: sorted search
   :dedent: 8
   :start-after: start SORTSEARCH
   :end-before: end SORTSEARCH

Paginated search using Virtual List View
----------------------------------------
Virtual List View provides a window into an ordered result set rather than
requiring the client to retrieve every preceding entry. The helper combines
Virtual List View with server-side sorting and returns the result in pages.

.. literalinclude:: search.py
   :language: python
   :caption: paginated search
   :dedent: 8
   :start-after: start VLVSEARCH
   :end-before: end VLVSEARCH

Get single object
-----------------
The ``get()`` helper performs a base-scope search for one entry and returns its
attributes. It is convenient when the distinguished name is already known
and the caller expects a single result.

.. literalinclude:: search.py
   :language: python
   :caption: get object
   :dedent: 8
   :start-after: start GETOBJ
   :end-before: end GETOBJ

Get single attribute of certain object
--------------------------------------
The ``get_attr()`` helper retrieves one attribute from a known entry. It avoids
transferring unrelated attributes and supports attribute aliases understood by
the server or schema.

.. literalinclude:: search.py
   :language: python
   :caption: get attribute
   :dedent: 8
   :start-after: start GETATTR
   :end-before: end GETATTR

Count search results
--------------------
The ``count()`` convenience method returns the number of entries matching a
search without transferring the entries themselves. It uses the OpenLDAP
Search No-Op control internally and is preferable to handling that control
manually when only the count is needed.

.. literalinclude:: search.py
   :language: python
   :caption: count search results
   :dedent: 8
   :start-after: start COUNT
   :end-before: end COUNT

Search for unique results
-------------------------
Setting ``unique=True`` asserts that the search returns exactly one entry.
The operation raises ``NotUnique`` when multiple entries match and exposes the
matching results through the exception for further handling.

.. literalinclude:: search.py
   :language: python
   :caption: assert uniqueness search
   :dedent: 8
   :start-after: start UNIQUE
   :end-before: end UNIQUE

Check for entry existence
-------------------------
The ``exists()`` helper checks whether an entry can be found without requiring
the caller to process its attributes. It is useful for conditional creation
or deletion workflows.

.. literalinclude:: search.py
   :language: python
   :caption: Check if entry exists
   :dedent: 8
   :start-after: start EXISTS
   :end-before: end EXISTS

Error handling
--------------
Searches can fail when the base DN does not exist, the caller lacks access, or
the server rejects the filter or operation. Catch the corresponding LDAP
exception, such as ``NoSuchObject``, when the application can recover from the
condition.

.. literalinclude:: search.py
   :language: python
   :caption: Error handling for not existing search bases
   :dedent: 8
   :start-after: start ERRORS
   :end-before: end ERRORS
