KDIR ?= /lib/modules/$(shell uname -r)/build
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))
CC = gcc
CFLAGS = -I. -g -O2 -I/usr/src/linux-headers-6.2.0-25-generic/tools/bpf/resolve_btfids/libbpf/include/\
										-I/usr/src/linux-headers-6.2.0-25/tools/lib/bpf/
										
LFLAGS = -L//usr/src/linux-headers-6.2.0-25-generic/tools/bpf/resolve_btfids/libbpf -lbpf -lelf -lz


KERNEL_SOURCES = $(wildcard *kern.c)
USER_SOURCES = $(wildcard *user.c)

KERNEL_OBJECTS = $(KERNEL_SOURCES:%.c=%.o)
EXECUTABLES = $(USER_SOURCES:%user.c=%)

CLANG_FLAGS = -I. \
	-I/usr/src/linux-headers-6.2.0-20/arch/alpha/include\
	-I/usr/src/linux-headers-6.2.0-25-generic/tools/bpf/resolve_btfids/libbpf/include/ \
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-g -O2 -emit-llvm

all: $(KERNEL_OBJECTS) $(EXECUTABLES)

%kern.o: %kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - | \
		$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

%: %user.c
	$(CC) $(CFLAGS) $< $(LFLAGS) -o $@

clean:
	rm -f $(KERNEL_OBJECTS) $(EXECUTABLES)
