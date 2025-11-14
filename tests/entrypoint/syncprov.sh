#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable syncprov overlay in OpenLDAP
set -e

cat > /tmp/syncprov-overlay.ldif << 'EOF'
dn: cn=module{7},cn=config
objectClass: olcModuleList
cn: module{1}
olcModuleLoad: syncprov

dn: olcOverlay=syncprov,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcSyncProvConfig
olcOverlay: syncprov
olcSpCheckpoint: 1000 1
olcSpSessionlog: 1000
# olcSpNoPresent
# olcSpReloadHint
# olcSpSessionlogSource
EOF

echo "Enabling syncprov overlay in OpenLDAP configuration..."
if slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep -q syncprov
then
    echo "syncprov overlay is already configured."
    exit 0
else
    slapadd -F /opt/bitnami/openldap/etc/slapd.d -b cn=config -l /tmp/syncprov-overlay.ldif || {
        echo "NOTICE: slapadd failed to load syncprov overlay. Check the cn=module{N}"
        slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep cn=module
        exit 1
    }
fi

echo "syncprov overlay has been configured."
