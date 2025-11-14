#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable constraint overlay in OpenLDAP
set -e

cat > /tmp/constraint-overlay.ldif << 'EOF'
dn: cn=module{2},cn=config
objectClass: olcModuleList
cn: module{1}
olcModuleLoad: constraint

dn: olcOverlay=constraint,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcConstraintConfig
olcOverlay: constraint
olcConstraintAttribute: uidNumber regex ^[^0]+[0-9]*$
olcConstraintAttribute: gidNumber regex ^[^0]+[0-9]*$
# olcConstraintAllowEmpty
EOF

echo "Enabling constraint overlay in OpenLDAP configuration..."
if slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep -q constraint
then
    echo "constraint overlay is already configured."
    exit 0
else
    slapadd -F /opt/bitnami/openldap/etc/slapd.d -b cn=config -l /tmp/constraint-overlay.ldif || {
        echo "NOTICE: slapadd failed to load constraint overlay. Check the cn=module{N}"
        slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep cn=module
        exit 1
    }
fi

echo "constraint overlay has been configured."
