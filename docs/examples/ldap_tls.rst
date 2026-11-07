TLS configuration
-----------------

FreeIAM uses OpenLDAP's TLS implementation. TLS protects LDAP traffic only
when the connection uses ``ldaps://`` or STARTTLS has completed successfully.
Setting TLS options alone does not encrypt an ``ldap://`` connection.

.. warning::

   Never disable server certificate verification to work around certificate
   errors. Configure the correct trust anchors and use a DNS name matching
   the server certificate. Do not send bind credentials over plaintext LDAP.

Configuring TLS
~~~~~~~~~~~~~~~

Call ``set_tls()`` before establishing the TLS session. It sets libldap TLS
options and explicitly creates a new client TLS context using
``TLSOption.NewContext``. This last step is essential:
OpenLDAP may otherwise ignore pending TLS option changes.

Because TLS settings are global, configure them before creating connections
and avoid modifying them concurrently in applications using multiple
connections. Existing connections and TLS contexts should not be expected to
pick up subsequent global changes.

``None`` means that FreeIAM does not explicitly set that option. It does
*not* necessarily mean that the option is disabled or that libldap uses a
particular secure value: system configuration and the TLS backend may apply.

.. list-table:: ``set_tls()`` / ``set_global_tls`` parameters
   :header-rows: 1
   :widths: 20 18 62

   * - Parameter
     - Default
     - Meaning and security considerations
   * - ``ca_certfile``
     - ``None``
     - Path to a PEM file containing trusted CA certificates. This is for
       verifying the LDAP server, not for sending a client certificate.
   * - ``ca_certdir``
     - ``None``
     - Directory of trusted CA certificates. The expected layout and hashed
       filenames depend on the TLS backend; an arbitrary directory of PEM
       files may not work.
   * - ``certfile``
     - ``None``
     - Client certificate (typically PEM) for mutual TLS authentication.
       Normally supply it together with ``keyfile``.
   * - ``keyfile``
     - ``None``
     - Private key corresponding to ``certfile``. Protect this file with
       restrictive filesystem permissions.
   * - ``require_cert``
     - ``TLSRequireCert.Demand``
     - Require successful server certificate verification. ``Hard`` and
       ``Demand`` are equivalent for client-side verification. ``Never``
       disables verification and is unsafe for production.
   * - ``require_san``
     - ``TLSRequireCert.Demand``
     - Controls server identity verification using certificate Subject
       Alternative Names (SAN). By default, a matching SAN is required;
       fallback to the certificate Common Name (CN) is not permitted.
       See :class:`TLSRequireCert` for available verification policies.
   * - ``minimum_protocol``
     - ``TLSProtocol.TLS12``
     - Minimum permitted TLS protocol version. TLS 1.2 or newer is
       recommended. Availability depends on the installed libldap and TLS
       backend. ``None`` leaves the backend/system policy in effect.
   * - ``cipher_suite``
     - ``None``
     - Backend-specific cipher configuration string. OpenSSL and GnuTLS
       syntax differ; TLS 1.3 cipher configuration may be handled separately.
       Prefer a maintained system policy unless customization is required.
   * - ``crlfile``
     - ``None``
     - Path to a certificate revocation list, where supported by the TLS
       backend.
   * - ``crl_check``
     - ``None``
     - Certificate revocation list checking policy. Common modes are no
       checking, checking the peer certificate, or checking the whole chain.
       CRL checking requires appropriately available and maintained CRLs;
       it is not enabled merely by supplying a CA certificate.

.. note::

   The precise availability of SAN, protocol, cipher and CRL options depends
   on the OpenLDAP version and TLS backend. Errors may occur when the TLS
   context is created or when the TLS handshake starts.

TLS security pitfalls
~~~~~~~~~~~~~~~~~~~~~

* STARTTLS requires LDAP protocol version 3. A successful call to
  ``set_tls()`` does not initiate STARTTLS; explicitly await ``start_tls()``
  before binding with credentials.
* Use ``ldaps://`` for TLS from connection establishment, normally on port
  636. An ``ldap://`` URI does not become LDAPS merely because TLS options
  were configured.
* A self-signed certificate is not automatically invalid. It can be trusted
  when explicitly configured as a trust anchor and its server identity
  matches the requested hostname.
* A trusted CA alone does not replace hostname verification. Do not disable
  ``require_cert`` or ``require_san`` to silence name mismatches.
* ``TLSOption.NewContext`` uses ``0`` for a client TLS context. Value ``1``
  is for a server-side context and must not be substituted.
* Once a TLS session is established, changing TLS options cannot retrofit
  that session. Create a fresh connection after changing the configuration.
* OpenLDAP 2.6 and later can expose more detailed TLS failures through the
  LDAP diagnostic message, depending on the failure and backend.

See also the OpenLDAP ``ldap.conf(5)`` documentation for the TLS options
and their backend-specific semantics.
