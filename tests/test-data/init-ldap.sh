#!/bin/bash
# LDAP Test Data Initialization Script
# This script loads test data into the OpenLDAP test container

set -e

echo "Waiting for LDAP server to be ready..."
timeout=30
while [ $timeout -gt 0 ]; do
    if ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "dc=example,dc=com" "(objectClass=*)" >/dev/null 2>&1; then
        echo "LDAP server is ready!"
        break
    fi
    echo "Waiting... ($timeout seconds remaining)"
    sleep 1
    timeout=$((timeout - 1))
done

if [ $timeout -eq 0 ]; then
    echo "ERROR: LDAP server failed to become ready"
    exit 1
fi

echo "Loading test data into LDAP..."
ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -f "$(dirname "$0")/init-ldap.ldif"

echo "Test data loaded successfully!"

echo "Verifying test users..."
ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "ou=users,dc=example,dc=com" "(uid=testuser)"

echo "LDAP test data initialization complete!"
