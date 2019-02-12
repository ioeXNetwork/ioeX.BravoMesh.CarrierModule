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
    echo "git clone ${PACKAGE_URL} ${DEPS_DIR}/${PACKAGE}"
    git clone ${PACKAGE_URL} ${DEPS_DIR}/${PACKAGE}
    echo "cd ${DEPS_DIR}/${PACKAGE}"
    cd ${DEPS_DIR}/${PACKAGE}
    echo "git checkout ${BRANCH}"
    git checkout ${BRANCH}
    echo "cd ../.."
    cd ../..
fi

exit 0
