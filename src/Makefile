ifeq ($(CC),cc)
    CC = clang
endif
ifeq ($(CC),gcc)
    CC = clang
endif
CC ?= clang

# XXX: -Wunused-but-set-variable doesn't work
# See: http://llvm.org/bugs/show_bug.cgi?id=9824
# -fcolor-diagnostics

CFLAGS := -Wall -Wextra \
-Wshadow -Wtrigraphs -Wunreachable-code -Wno-unused-label \
-Wwrite-strings -Wstrict-aliasing \
-Wstrict-overflow -Warray-bounds \
-Wpointer-arith -Wvolatile-register-var \
-Wno-unused-parameter \
-fPIC -g -O2 -Os -fno-strict-aliasing $(CFLAGS)

ifneq ($(strip $(LESS)),)
    CFLAGS += -fcolor-diagnostics
endif

LDFLAGS = -shared
OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c))

HEADERS = $(wildcard *.h)

sdn_sensor: $(OBJECTS)
	@echo $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) -lbsd -ljson-c -llog4c -lpcap -lpcre

$(OBJECTS): $(HEADERS)

.PHONY: clean
clean:
	@echo 'Cleaning sdn_sensor...'
	@rm -f sdn_sensor *.o
