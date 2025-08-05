.. _search-examples:

Search and Pagination
=====================

Search and receive objects and attributes
-----------------------------------------

.. literalinclude:: search.py
   :language: python
   :caption: subtree search
   :dedent: 8
   :start-after: start SEARCH
   :end-before: end SEARCH

Search iterative
----------------
.. literalinclude:: search.py
   :language: python
   :caption: iterative search
   :dedent: 8
   :start-after: start ITERSEARCH
   :end-before: end ITERSEARCH

Search for DN only
------------------
.. literalinclude:: search.py
   :language: python
   :caption: search for DN
   :dedent: 8
   :start-after: start DNSEARCH
   :end-before: end DNSEARCH

Paginated search using SimplePagedResult
----------------------------------------
.. literalinclude:: search.py
   :language: python
   :caption: simple paginated search
   :dedent: 8
   :start-after: start PAGEDSEARCH
   :end-before: end PAGEDSEARCH

Server-Side Sort search
-----------------------
.. literalinclude:: search.py
   :language: python
   :caption: sorted search
   :dedent: 8
   :start-after: start SORTSEARCH
   :end-before: end SORTSEARCH

Paginated search using Virtual List View
----------------------------------------
.. literalinclude:: search.py
   :language: python
   :caption: paginated search
   :dedent: 8
   :start-after: start VLVSEARCH
   :end-before: end VLVSEARCH

Get single object
-----------------
.. literalinclude:: search.py
   :language: python
   :caption: get object
   :dedent: 8
   :start-after: start GETOBJ
   :end-before: end GETOBJ

Get single attribute of certain object
--------------------------------------
.. literalinclude:: search.py
   :language: python
   :caption: get attribute
   :dedent: 8
   :start-after: start GETATTR
   :end-before: end GETATTR

Search for unique results
-------------------------
.. literalinclude:: search.py
   :language: python
   :caption: assert uniqueness search
   :dedent: 8
   :start-after: start UNIQUE
   :end-before: end UNIQUE

Check for entry existance
-------------------------
.. literalinclude:: search.py
   :language: python
   :caption: Check if entry exists
   :dedent: 8
   :start-after: start EXISTS
   :end-before: end EXISTS

Error handling
--------------
.. literalinclude:: search.py
   :language: python
   :caption: Error handling for not existing search bases
   :dedent: 8
   :start-after: start ERRORS
   :end-before: end ERRORS
