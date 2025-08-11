#!/bin/bash
OS_NAME=""
OS_VERSION=""
HOSTNAME=$(hostname)

if [ -f /etc/os-release ]; then
    source /etc/os-release
    OS_NAME=$NAME
    OS_VERSION=$VERSION_ID
elif [ -f /etc/redhat-release ]; then
    OS_NAME=$(cat /etc/redhat-release | cut -d' ' -f1)
    OS_VERSION=$(cat /etc/redhat-release | sed -r 's/.*release ([0-9.]+).*/\1/')
else
    OS_NAME="Unknown"
    OS_VERSION="Unknown"
fi

echo "$HOSTNAME,$OS_NAME,$OS_VERSION"
