ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG   ?= clang
BPFTOOL ?= bpftool
KERNEL_HEADERS ?= /lib/modules/$(shell uname -r)/build

SRC     := src
OUT     := .output
INCLUDE := include

# When using vmlinux.h, do NOT add kernel UAPI headers — they conflict.
# vmlinux.h is self-contained and provides all required types.
BPF_CFLAGS := \
    -g -O2 -Wall \
    -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I$(INCLUDE)

PROGRAMS := privesc bpf_loader container kmod

.PHONY: all clean vmlinux

all: vmlinux $(addprefix $(OUT)/, $(addsuffix .bpf.o, $(PROGRAMS)))

vmlinux: $(INCLUDE)/vmlinux.h
$(INCLUDE)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUT)/%.bpf.o: $(SRC)/%.bpf.c | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUT):
	mkdir -p $(OUT)

clean:
	rm -rf $(OUT)
