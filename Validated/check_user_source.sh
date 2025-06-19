#!/bin/bash

# Check if a username was passed
if [ -z "$1" ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

USERNAME="$1"

# Check if user exists in /etc/passwd (local account)
if grep -q "^${USERNAME}:" /etc/passwd; then
    echo "User '$USERNAME' is a LOCAL account (found in /etc/passwd)."
    exit 0
fi

# Check if user exists via getent (could be AD/LDAP)
if getent passwd "$USERNAME" > /dev/null; then
    # Optionally extract info to show domain affiliation
    USER_INFO=$(getent passwd "$USERNAME")
    echo "User '$USERNAME' is a NON-LOCAL account (likely from Active Directory or LDAP)."
    echo "Details: $USER_INFO"
    exit 0
fi

echo "User '$USERNAME' not found on this system."
exit 1

