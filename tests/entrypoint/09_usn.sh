#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable usn overlay in OpenLDAP
set -e

CONFIG_DIR=/opt/bitnami/openldap/etc/slapd.d

cat > /tmp/usn-overlay.ldif << 'EOF'
dn: cn=module{9},cn=config
objectClass: olcModuleList
cn: module{9}
olcModuleLoad: usn

dn: olcOverlay=usn,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
olcOverlay: usn
EOF

echo "Enabling usn overlay in OpenLDAP configuration..."
if slapcat -F "$CONFIG_DIR" -b cn=config | grep -q usn
then
    echo "usn overlay is already configured."
    exit 0
else
    slapadd -F "$CONFIG_DIR" -b cn=config -l /tmp/usn-overlay.ldif || {
        echo "NOTICE: slapadd failed to load usn overlay. Check the cn=module{N}"
        slapcat -F "$CONFIG_DIR" -b cn=config | grep cn=module
        exit 1
    }
fi

echo "usn overlay has been configured."
