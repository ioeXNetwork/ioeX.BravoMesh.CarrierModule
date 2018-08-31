#!/bin/sh

#argv1: HOST
#argv2: ARCH
#argv3: HOST_COMPILER

getConfigureCmd() {
    case $1,$2 in
        "Darwin",*)
            _TOOL="./configure"
            ;;
        "Linux","x86_64"| "Raspbian","armv7l")
            _TOOL="./configure --enable-epoll=yes"
            ;;
        "Linux",*)
            _TOOL="./configure --enable-epoll=yes --host=$3"
            ;;
        "Android",*)
            _TOOL="./configure --host=$3 --enable-epoll=yes --disable-rt"
            ;;
        "iOS","x86")
            _TOOL="./configure --host=\"i386-apple-darwin_ios\""
            ;;
        "iOS","x86_64")
            _TOOL="./configure --host=\"x86_64-apple-darwin_ios\""
            ;;
        "iOS","arm" | "iOS","arm64")
            _TOOL="./configure --host=${3/D/d}"
            ;;
        *,*)
            echo "Unsupported platform $1:$2"
            exit 1;;
    esac

    echo ${_TOOL}
}

if [ x"$1" = x"command" ]; then
    getConfigureCmd $2 $3 $4
    exit 0
fi

exit 0

