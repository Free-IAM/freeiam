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

The ``SimplePagedResultsControl``, ``VirtualListViewControl``, and ``ServerSideSortingControl`` are integrated into the ``search()``, ``search_paged()``, and ``search_paginated()`` methods.

Refer to the :ref:`search-examples` for practical usage.

PreRead and PostRead Controls
-----------------------------

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

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Assertion Control
   :start-after: use Assertion Control
   :end-before: end use Assertion Control


RelaxRules Control
------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: RelaxRules Control
   :start-after: use RelaxRules Control
   :end-before: end use RelaxRules Control


Proxy Authorization Control
----------------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: ProxyAuthz Control
   :start-after: use ProxyAuthz Control
   :end-before: end use ProxyAuthz Control


MatchedValues Control
---------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: MatchedValues Control
   :start-after: use MatchedValues Control
   :end-before: end use MatchedValues Control


PersistentSearch Control
------------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: PersistentSearch Control (not supported by OpenLDAP)
   :start-after: use PersistentSearch Control
   :end-before: end use PersistentSearch Control


SessionTracking Control
-----------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: SessionTracking Control (not supported by OpenLDAP)
   :start-after: use SessionTrackingControl
   :end-before: end use SessionTrackingControl


GetEffectiveRights Control
--------------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: GetEffectiveRights Control
   :start-after: use GetEffectiveRights Control
   :end-before: end use GetEffectiveRights Control


Authorization Identity Control
------------------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Authorization Identity Control
   :start-after: use Authorization Identity Control
   :end-before: end use Authorization Identity Control


Dereference Control
-------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: Dereference Control (not supported by OpenLDAP)
   :start-after: use Dereference Control
   :end-before: end use Dereference Control


Manage DSA Information Tree Control
-----------------------------------

.. literalinclude:: controls.py
   :language: python
   :dedent: 4
   :caption: ManageDSAIT Control
   :start-after: use ManageDSAITControl
   :end-before: end use ManageDSAITControl
