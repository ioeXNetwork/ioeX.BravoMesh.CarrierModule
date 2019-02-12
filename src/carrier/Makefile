LIBNAME = libIOEXcarrier

PREFIX ?= /usr/local
INCLUDE_PATH ?= include
LIBRARY_PATH ?= lib
BINARY_PATH  ?= bin
HOST ?= $(uname -s)

INSTALL_INCLUDE_PATH = $(DESTDIR)$(PREFIX)/$(INCLUDE_PATH)
INSTALL_LIBRARY_PATH = $(DESTDIR)$(PREFIX)/$(LIBRARY_PATH)
INSTALL_BINARY_PATH  = $(DESTDIR)$(PREFIX)/$(BINARY_PATH)

INSTALL ?= cp -a
FLATCC  ?= flatcc

IOEX_CFLAGS := -DCARRIER_BUILD -DIOEX_BUILD -DIOEX_CARRIER_VERSION=\"$(IOEX_CARRIER_VERSION)\" -DIOEX_CARRIER_LAST_COMMIT=\"$(IOEX_CARRIER_LAST_COMMIT)\" -DIOEX_CARRIER_BUILD_TIME=\"$(IOEX_CARRIER_BUILD_TIME)\"
CFLAGS := $(CFLAGS) $(IOEX_CFLAGS) -I. -I../common -Idht -I$(INSTALL_INCLUDE_PATH) -fvisibility=hidden -fPIC -Wall  -Wstrict-prototypes -Wwrite-strings
LDFLAGS := $(LDFLAGS) -fvisibility=hidden
LIBS   := -lIOEXcommon -ltoxcore -lsodium -lm -lflatccrt

ifneq (, $(findstring $(HOST), Darwin iOS))
	CFLAGS := $(CFLAGS) -Wno-pointer-sign
endif

ifeq ($(HOST), Linux)
	CFLAGS := $(CFLAGS) -Wno-strict-prototypes
endif

ifeq ($(HOST), Android)
	CFLAGS := $(CFLAGS) -Wno-format -Wno-strict-prototypes
	LIBS := $(LIBS) -llog
else
ifeq (, $(findstring $(HOST), Darwin iOS))
	LIBS := $(LIBS) -lpthread
endif
endif

STLIBNAME = $(LIBNAME).a

ifneq (, $(findstring $(HOST), Darwin iOS))
	DYLIBNAME = $(LIBNAME).dylib
else
	DYLIBNAME = $(LIBNAME).so
endif

IOEXcp_generated.h: IOEXcp.fbs
	${FLATCC} --outfile $@ -a $< 

IOEXcp.o : IOEXcp_generated.h

SRCS = IOEX_carrier.c IOEXcp.c dht/dht.c

OBJS = $(SRCS:.c=.o)

LOBJS = $(SRCS:.c=.lo)

.SUFFIXES:
.SUFFIXES: .c .lo .o

HEADERS = IOEX_carrier.h

.PHONY: all clean install

all: $(DYLIBNAME) $(STLIBNAME)

$(DYLIBNAME): $(OBJS)
	$(CC) -shared $(LDFLAGS) -o $@ $(OBJS) -L$(INSTALL_LIBRARY_PATH) $(LIBS)

$(STLIBNAME): $(LOBJS)
	$(AR) rcs $@ $^

.c.o:
	$(CC) -c $(CFLAGS) -DCARRIER_DYNAMIC -o $@ $<

.c.lo:
	$(CC) -c $(CFLAGS) -DCARRIER_STATIC -o $@ $<

install: all
	mkdir -p $(INSTALL_LIBRARY_PATH) $(INSTALL_INCLUDE_PATH)
	$(INSTALL) $(HEADERS) $(INSTALL_INCLUDE_PATH)
	$(INSTALL) $(DYLIBNAME) $(INSTALL_LIBRARY_PATH)
	$(INSTALL) $(STLIBNAME) $(INSTALL_LIBRARY_PATH)

clean:
	rm -rf $(DYLIBNAME) $(STLIBNAME)
	rm -rf IOEXcp_generated.h
	rm -rf *.o *.lo
	rm -rf dht/*.o dht/*.lo
