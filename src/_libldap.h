// SPDX-FileCopyrightText: 2026 Florian Best
// SPDX-License-Identifier: MIT OR Apache-2.0
#ifndef FREEIAM_LIBLDAP_H
#define FREEIAM_LIBLDAP_H

#include <Python.h>
#include <lber.h>
#include <ldap.h>

/*
 * OpenLDAP < 2.7 does not expose ldap_pvt_put_filter()
 */
#if defined(LDAP_VENDOR_VERSION) && LDAP_VENDOR_VERSION < 20700
LDAP_F(int) ldap_pvt_put_filter LDAP_P((BerElement * ber, const char *str));
#endif

PyObject *FREEIAM_ldap_pvt_put_filter(PyObject *module, PyObject *args);

#endif
