// SPDX-FileCopyrightText: 2026 Florian Best
// SPDX-License-Identifier: MIT OR Apache-2.0

#include "_libldap.h"
#include <Python.h>

/*
 * freeiam._libdap.ldap_pvt_put_filter
 *
 * Encode an LDAP filter string as a BER-encoded Filter (RFC 4511).
 *
 * Python signature:
 *     ldap_pvt_put_filter(ldap_filter: str) -> bytes
 *
 * Raises TypeError for invalid arguments, ValueError for an invalid
 * LDAP filter, and MemoryError on allocation failure.
 */
PyObject *
FREEIAM_ldap_pvt_put_filter(PyObject *module, PyObject *args)
{
    const char *filter;
    BerElement *ber = NULL;
    struct berval bv = {0};
    PyObject *result = NULL;
    int rc;

    if (!PyArg_ParseTuple(args, "s:ldap_pvt_put_filter", &filter))
        return NULL;

    ber = ber_alloc_t(LBER_USE_DER);
    if (ber == NULL)
        return PyErr_NoMemory();

    rc = ldap_pvt_put_filter(ber, filter);
    if (rc != 0) {
        PyErr_SetString(PyExc_ValueError, "Bad LDAP filter");
        goto cleanup;
    }

    rc = ber_flatten2(ber, &bv, 0);
    if (rc == -1) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to flatten BER-encoded LDAP filter");
        goto cleanup;
    }

    result = PyBytes_FromStringAndSize(bv.bv_val, bv.bv_len);

cleanup:
    ber_free(ber, 1);
    return result;
}

/*
 * freeiam._libdap.ldap_tls_in_place
 *
 * Check if connection is established via TLS
 *
 * Python signature:
 *     ldap_tls_in_place(conn) -> bool
 *
 * Raises TypeError for invalid arguments.
 */
//PyObject *
//FREEIAM_ldap_tls_inplace(LDAPObject *self)
//{
//    PyObject *conn;
//
//    if (!PyArg_ParseTuple(args, "O:ldap_tls_inplace", &conn))
//        return NULL;
//
//    return PyBool_FromLong(ldap_tls_inplace(conn));
//}

static PyMethodDef freeiam_libldap_methods[] = {
    {"ldap_pvt_put_filter", FREEIAM_ldap_pvt_put_filter, METH_VARARGS, "Encode an LDAP search filter using libldap."},
    // {"ldap_tls_inplace", FREEIAM_ldap_tls_inplace, METH_VARARGS, "Check if connection is established via TLS."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {PyModuleDef_HEAD_INIT, "_libldap", NULL, -1, freeiam_libldap_methods};

PyMODINIT_FUNC
PyInit__libldap(void)
{
    return PyModule_Create(&moduledef);
}
