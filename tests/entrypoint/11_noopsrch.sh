#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable No-Op Search overlay in OpenLDAP
set -e

CONFIG_DIR=/opt/bitnami/openldap/etc/slapd.d

cat > /tmp/noopsrch-overlay.ldif << 'EOF'
dn: cn=module{10},cn=config
objectClass: olcModuleList
cn: module{10}
olcModuleLoad: noopsrch

dn: olcOverlay=noopsrch,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
olcOverlay: noopsrch
EOF

echo "Enabling No-Op Search overlay in OpenLDAP configuration..."
echo "Loading No-Op Search overlay with slapadd..."

if slapcat -F "$CONFIG_DIR" -b cn=config | grep -q '^olcOverlay: noopsrch$'
then
    echo "No-Op Search overlay is already configured."
    exit 0
else
    slapadd -F "$CONFIG_DIR" -b cn=config -l /tmp/noopsrch-overlay.ldif || {
        echo "NOTICE: slapadd failed to load No-Op Search overlay."
        echo "Check the cn=module{N} index and module availability."
        slapcat -F "$CONFIG_DIR" -b cn=config | grep 'cn=module' || true
        exit 1
    }
fi

echo "No-Op Search overlay has been configured."
