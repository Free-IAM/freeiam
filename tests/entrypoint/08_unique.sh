#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable unique overlay in OpenLDAP
set -e

CONFIG_DIR=/opt/bitnami/openldap/etc/slapd.d

cat > /tmp/unique-overlay.ldif << 'EOF'
dn: cn=module{8},cn=config
objectClass: olcModuleList
cn: module{8}
olcModuleLoad: unique

dn: olcOverlay=unique,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcUniqueConfig
olcOverlay: unique
olcUniqueUri: ldap:///dc=freeiam,dc=org?uidNumber?sub
EOF

echo "Enabling unique overlay in OpenLDAP configuration..."
if slapcat -F "$CONFIG_DIR" -b cn=config | grep -q unique
then
    echo "unique overlay is already configured."
    exit 0
else
    slapadd -F "$CONFIG_DIR" -b cn=config -l /tmp/unique-overlay.ldif || {
        echo "NOTICE: slapadd failed to load unique overlay. Check the cn=module{N}"
        slapcat -F "$CONFIG_DIR" -b cn=config | grep cn=module
        exit 1
    }
fi

echo "unique overlay has been configured."
