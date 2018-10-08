#!/bin/sh

PACKAGE_URL=$1
PACKAGE=$2
BRANCH=$3
DEPS_DIR=$4

if [ ! -e ${DEPS_DIR} ]; then
   mkdir -p ${DEPS_DIR}
fi

if [ ! -e ${DEPS_DIR}/${PACKAGE} ]; then
    mkdir -p ${DEPS_DIR}
    echo "git clone -b ${BRANCH} ${PACKAGE_URL} ${DEPS_DIR}/${PACKAGE}"
    git clone ${PACKAGE_URL} ${DEPS_DIR}/${PACKAGE}
fi

exit 0
