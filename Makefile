# SPDX-License-Identifier: MIT
CLANG ?= clang
LLC ?= llc
BPFOBJ = bpf/spa_kern.bpf.o
TCBPFOBJ = bpf/spa_kern_tc.bpf.o
VMLINUX = bpf/vmlinux.h
SKEL = src/spa_kern.skel.h
SKEL_TC = src/spa_kern_tc.skel.h
LOADER = build/spale

BPFTOOL ?= bpftool
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86
USR_CFLAGS ?= -O2 -g -Wall -Werror
USR_LDFLAGS ?=

BASE_LDLIBS := -lbpf -lelf -lz -lssl -lcrypto

ifeq ($(STATIC),1)
USR_LDFLAGS += -static
USR_LDLIBS := -Wl,-Bstatic -lbpf -lelf -lz -lzstd -lssl -lcrypto -ldl -pthread
USR_CFLAGS += -DNO_NSS
else
USR_LDLIBS ?= $(BASE_LDLIBS)
endif

PREFIX ?= /usr/local
SYSCONFDIR ?= /etc/spale

.PHONY: all clean

all: $(VMLINUX) $(BPFOBJ) $(TCBPFOBJ) $(SKEL) $(SKEL_TC) $(LOADER)

$(BPFOBJ): bpf/spa_kern.bpf.c include/spa_common.h $(VMLINUX)
	@mkdir -p bpf
	$(CLANG) $(BPF_CFLAGS) -Iinclude -Ibpf -c $< -o $@

$(TCBPFOBJ): bpf/spa_kern_tc.bpf.c include/spa_common.h $(VMLINUX)
	@mkdir -p bpf
	$(CLANG) $(BPF_CFLAGS) -Iinclude -Ibpf -c $< -o $@

$(VMLINUX):
	@mkdir -p bpf
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(SKEL): $(BPFOBJ)
	@mkdir -p src
	$(BPFTOOL) gen skeleton $< > $@

$(SKEL_TC): $(TCBPFOBJ)
	@mkdir -p src
	$(BPFTOOL) gen skeleton $< > $@


$(LOADER): src/loader.c src/hpke.h src/hpke_openssl.c $(SKEL) $(SKEL_TC) include/spa_common.h
	@mkdir -p build
	$(CC) $(USR_CFLAGS) -DDEFAULT_SYSCONFDIR=\"$(SYSCONFDIR)\" -DDEFAULT_CONF_PATH=\"$(SYSCONFDIR)/spale.conf\" -DDEFAULT_SERVER_KEY=\"$(SYSCONFDIR)/server.key\" -DDEFAULT_CLIENTS_DIR=\"$(SYSCONFDIR)/clients\" -Iinclude -Isrc -c src/loader.c -o build/loader.o
	$(CC) $(USR_CFLAGS) -Iinclude -Isrc -c src/hpke_openssl.c -o build/hpke_openssl.o
	$(CC) $(USR_LDFLAGS) build/loader.o build/hpke_openssl.o -o $(LOADER) $(USR_LDLIBS)

clean:
	rm -f $(BPFOBJ) $(TCBPFOBJ) $(SKEL) $(VMLINUX) build/*.o $(LOADER)

install: all
	install -Dm0755 $(LOADER) $(DESTDIR)$(PREFIX)/sbin/spale


# Fuzzing targets (requires clang, libFuzzer, ASan/UBSan, and OpenSSL dev)
.PHONY: fuzz fuzz-run

FUZZ_DIR := fuzz
FUZZ_BIN := build/fuzz_hpke

fuzz: $(FUZZ_BIN)

$(FUZZ_BIN): src/hpke_openssl.c src/hpke.h
	@mkdir -p build $(FUZZ_DIR)
	$(CLANG) -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -Iinclude -Isrc -g -O1 \
		src/hpke_openssl.c $(FUZZ_DIR)/fuzz_hpke.c -o $(FUZZ_BIN) -lssl -lcrypto

fuzz-run: $(FUZZ_BIN)
	$(FUZZ_BIN) -max_total_time=30 -print_final_stats=1 -rss_limit_mb=2048


