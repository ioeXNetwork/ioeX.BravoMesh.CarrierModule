PREFIX ?= /usr/local

PREFIX := $(abspath $(PREFIX))
HOST   ?= $(uname -s)
ARCH   ?= $(uname -m)

export IOEX_CARRIER_VERSION = "0.7.0"
export IOEX_CARRIER_LAST_COMMIT = $(shell git log --pretty=format:"%h" | head -1)
export IOEX_CARRIER_BUILD_TIME = $(shell date "+%Y/%m/%d-%H:%M:%S")

MODULES = common carrier session

all: message install

message:
	-echo "\033[0;31m IMPORTANT:\033[0;33m Make sure update IOEX_CARRIER_VERSION when release!\033[0m"

install:
	@for i in $(MODULES) ; do \
	(cd $$i && echo "making in $$i..." && \
	PREFIX=$(PREFIX) $(MAKE) install) || exit 1; \
	done;

clean:
	@for i in $(MODULES) ; do \
	(cd $$i && echo "making in $$i..." && \
	PREFIX=$(PREFIX) $(MAKE) clean) || exit 1; \
	done;
