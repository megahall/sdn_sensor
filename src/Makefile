ifeq ($(CC),cc)
    CC = clang
endif
ifeq ($(CC),gcc)
    CC = clang
endif
CC     ?= clang

RTE_SDK ?= $(HOME)/src/dpdk

# XXX: -Wunused-but-set-variable doesn't work
# See: http://llvm.org/bugs/show_bug.cgi?id=9824
# -fcolor-diagnostics
# -O2 -Os
#
WARNINGS = \
-Wall -Wextra \
-Wshadow -Wtrigraphs -Wunreachable-code -Wno-unused-label \
-Wwrite-strings -Wstrict-aliasing \
-Wstrict-overflow -Warray-bounds \
-Wpointer-arith -Wvolatile-register-var \
-Wno-unused-parameter

FLAGS          = -fPIC -O0 -g -fno-strict-aliasing -pthread -march=native
INCLUDE_FILES  = -include $(RTE_SDK)/build/include/rte_config.h
INCLUDE_PATHS  = -I$(RTE_SDK)/build/include
CFLAGS        := $(WARNINGS) $(FLAGS) $(INCLUDE_FILES) $(INCLUDE_PATHS) $(CFLAGS)

# XXX: work around bugs in iwyu utility
IWYU_PATHS = -I/usr/local/include -I/usr/lib/llvm-3.4/lib/clang/3.4/include -I/usr/lib/gcc/x86_64-linux-gnu/4.8/include -I/usr/include/x86_64-linux-gnu -I/usr/include

ifneq ($(strip $(LESS)),)
    CFLAGS += -fcolor-diagnostics
endif

DPDK_LINK = -Wl,--whole-archive -Wl,--start-group -lintel_dpdk -Wl,--end-group -Wl,--no-whole-archive

LDFLAGS = -L$(RTE_SDK)/build/lib

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c))
HEADERS = $(wildcard *.h)

.PHONY: clean cproto iwyu

sdn_sensor: $(OBJECTS)
	@echo 'Linking sdn_sensor...'
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(DPDK_LINK) -lbsd -ldl -ljson-c -lm -lmsgpack -lnanomsg -lpcap -lpcre -lpthread -lrt

$(OBJECTS): $(HEADERS) $(SOURCES)

cproto:
	$(PWD)/../scripts/update-header-file.pl $(INCLUDE_PATHS) -- $(HEADERS)

iwyu: $(HEADERS) $(SOURCES)
	@echo 'Checking includes in sdn_sensor...'
	for file in $^; do iwyu ${CFLAGS} ${IWYU_PATHS} $$file; done;

clean:
	@echo 'Cleaning sdn_sensor...'
	@rm -f sdn_sensor *.o
