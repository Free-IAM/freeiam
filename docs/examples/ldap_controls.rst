Using LDAP Controls
===================

LDAP **controls** are optional extensions that modify the behavior of
standard operations. They are sent alongside requests to the server and
can influence how the operation is processed or how results are returned.

Controls can be used to request additional information, enforce certain
server-side policies, or enable features such as pagination and sorting.

This section demonstrates how to:

* Send controls with search and modification requests.
* Interpret and handle response controls returned by the server.

Controls are a powerful way to adapt LDAP operations to specific
application requirements without changing the protocol's core commands.

Apply controls to all operations of the connection
--------------------------------------------------

Controls can be passed explicitly with each operation, or applied globally to all operations via the connection object, as shown below:

.. literalinclude:: controls.py
   :language: python
   :start-after: use connection wide control
   :end-before: end use connection wide control

Simple Paged Results, Virtual List View, and Server-Side Sorting Controls
-------------------------------------------------------------------------

The Simple Paged Results control splits a large search result into pages. The
client sends the page size and the cookie returned by the previous response.

The Virtual List View control requests a window around a position or a
lexicographically selected value in a sorted result set. It is useful for
list widgets that need a small view of a large result set.

The Server-Side Sorting control asks the server to sort search results before
returning them. The server-side sorting and Virtual List View controls are
normally used together.

The ``SimplePagedResultsControl``, ``VirtualListViewControl``, and
``ServerSideSortingControl`` are integrated into the ``search()``,
``search_paged()``, and ``search_paginated()`` methods.

Refer to the :ref:`search-examples` for practical usage.

PreRead and PostRead Controls
-----------------------------

The Pre-Read control returns the selected attributes as they were stored
before a modification. The Post-Read control returns the selected attributes
after an add, modify, modify-DN, or delete operation. Both controls avoid a
separate search when the client needs to inspect the affected entry.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: PostRead Control
   :start-after: use PostRead Control
   :end-before: end use PostRead Control

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: PreRead Control
   :start-after: use PreRead Control
   :end-before: end use PreRead Control

Assertion Control
-----------------

The Assertion control makes an operation conditional on a filter matching the
target entry. If the assertion is false, the server rejects the operation
instead of applying a modification based on stale data.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Assertion Control
   :start-after: use Assertion Control
   :end-before: end use Assertion Control


RelaxRules Control
------------------

The Relax Rules control allows an authorized client to bypass selected schema
and update restrictions. It is an administrative control and should not be
made available to ordinary users.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: RelaxRules Control
   :start-after: use RelaxRules Control
   :end-before: end use RelaxRules Control


Proxy Authorization Control
----------------------------

The Proxy Authorization control makes the server evaluate an operation as
another authorization identity. The bound identity must have permission to
proxy as the requested identity.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: ProxyAuthz Control
   :start-after: use ProxyAuthz Control
   :end-before: end use ProxyAuthz Control


MatchedValues Control
---------------------

The Matched Values control limits returned attribute values to those matching
an assertion filter. Unlike a search filter, it does not filter out the entry;
it filters values within the requested attributes.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: MatchedValues Control
   :start-after: use MatchedValues Control
   :end-before: end use MatchedValues Control


Search No-Op Control
--------------------

The Search No-Op control evaluates a search without returning matching
entries. It counts matching entries and reports the number of search
continuations generated while processing the search. For counting entries,
prefer the ``Connection.count()`` convenience method. Use the control
directly when the response control or its continuation count is needed.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Search No-Op Control
   :start-after: use Search No-Op Control
   :end-before: end use Search No-Op Control


Password Policy Control
-----------------------

The Password Policy control returns password-policy warnings with a successful
authentication response and password-policy errors with a failed response.
Both paths need to be handled because the server can return the control with
an LDAP error. The same request control can be sent with a password change to
receive policy errors such as an insufficient password length.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Password Policy Control
   :start-after: use Password Policy control
   :end-before: end use Password Policy control


Netscape Password Status Controls
---------------------------------

The Netscape Password Expired and Password Expiring controls are response-only
controls. A server can attach them to an authentication response without the
client sending a corresponding request control.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Netscape Password Status Controls
   :start-after: use Netscape password status controls
   :end-before: end use Netscape password status controls


PersistentSearch Control
------------------------

The Persistent Search control keeps a search operation open and sends changes
that match the search as they occur. It can request only changes, or the
initial matching entries followed by changes. The example requests modify
notifications and is not supported by OpenLDAP.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: PersistentSearch Control (not supported by OpenLDAP)
   :start-after: use PersistentSearch Control
   :end-before: end use PersistentSearch Control


SessionTracking Control
-----------------------

The Session Tracking control attaches client session metadata to an LDAP
operation, such as the source address, source host, and a tracking identifier.
Servers can use this information for auditing and request correlation.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: SessionTracking Control
   :start-after: use SessionTrackingControl
   :end-before: end use SessionTrackingControl


GetEffectiveRights Control
--------------------------

The Get Effective Rights control asks the server to return the permissions of
the authorization identity on an entry and its attributes. The result is
server-specific and usually requires administrative privileges.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: GetEffectiveRights Control
   :start-after: use GetEffectiveRights Control
   :end-before: end use GetEffectiveRights Control


Authorization Identity Control
------------------------------

The Authorization Identity control requests the authorization identity that
the server assigned after authentication. This is useful when the bind name
and the effective identity can differ, for example with SASL or proxy
authorization.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Authorization Identity Control
   :start-after: use Authorization Identity Control
   :end-before: end use Authorization Identity Control


Dereference Control
-------------------

The Dereference control asks the server to resolve referenced entries while
returning a search result. It can include selected attributes from the
referenced entries. The example is not supported by OpenLDAP.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Dereference Control (not supported by OpenLDAP)
   :start-after: use Dereference Control
   :end-before: end use Dereference Control


Manage DSA Information Tree Control
-----------------------------------

The Manage DSA IT control asks the server to treat referral and knowledge
information entries as ordinary entries. This allows an authorized client to
read or modify the directory information tree instead of following referrals.

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: ManageDSAIT Control
   :start-after: use ManageDSAITControl
   :end-before: end use ManageDSAITControl
