#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable unique overlay in OpenLDAP
set -e

cat > /tmp/unique-overlay.ldif << 'EOF'
dn: cn=module{8},cn=config
objectClass: olcModuleList
cn: module{1}
olcModuleLoad: unique

dn: olcOverlay=unique,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcUniqueConfig
olcOverlay: unique
olcUniqueUri: ldap:///dc=freeiam,dc=org?uidNumber?sub
EOF

echo "Enabling unique overlay in OpenLDAP configuration..."
if slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep -q unique
then
    echo "unique overlay is already configured."
    exit 0
else
    slapadd -F /opt/bitnami/openldap/etc/slapd.d -b cn=config -l /tmp/unique-overlay.ldif || {
        echo "NOTICE: slapadd failed to load unique overlay. Check the cn=module{N}"
        slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep cn=module
        exit 1
    }
fi

echo "unique overlay has been configured."
