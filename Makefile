KDIR ?= /lib/modules/$(shell uname -r)/build
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

BIN := sockex1_kern.o
CLANG_FLAGS = -I. \
	-I/home/xdp-tutorial/common/\
	-I/usr/src/linux-headers-6.2.0-25-generic/tools/bpf/resolve_btfids/libbpf/include/ \
	-I/usr/src/linux-headers-6.2.0-20-generic/tools/bpf/resolve_btfids/libbpf/include/ \
	-I/usr/src/linux-headers-6.2.0-20-generic/arch/x86/include/generated/ \
	-I/usr/src/linux-headers-6.2.0-25/include \
	-I/usr/src/linux-headers-6.2.0-25/arch/x86/include/\
	-I/home/otman/TC/linux-next/tools/testing/selftests/\
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-g -O2 -emit-llvm

all: $(BIN)

%.o: %.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - | \
		$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

clean:
	rm -f *.o
