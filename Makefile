# kernelradar — top-level orchestration Makefile
# Wraps cargo + BPF build + system installation.

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
LIBDIR     ?= /var/lib/kernelradar
SYSTEMDDIR ?= /etc/systemd/system

CARGO     ?= cargo
INSTALL   ?= install
SYSTEMCTL ?= systemctl

BPF_DIR  := crates/kernelradar-bpf
BIN      := target/release/kernelradar

.PHONY: all bpf rust check clean install uninstall \
        service-start service-stop service-restart \
        service-status service-logs

all: bpf rust

# ── Build ────────────────────────────────────────────────────────────
bpf:
	$(MAKE) -C $(BPF_DIR)

# rust depends on bpf — the userspace `build.rs` hashes the .bpf.o
# files at compile time for integrity verification. Without this
# ordering, a first-time `make rust` records empty hashes and the
# daemon logs "no build-time hash recorded" at every startup.
rust: bpf
	$(CARGO) build --release

check:
	$(CARGO) check
	$(CARGO) clippy --workspace -- -D warnings || true

clean:
	$(CARGO) clean
	$(MAKE) -C $(BPF_DIR) clean

# ── Install ──────────────────────────────────────────────────────────
# Layout:
#   /usr/local/bin/kernelradar
#   /var/lib/kernelradar/bpf/{privesc,bpf_loader,container,kmod}.bpf.o
#   /etc/systemd/system/kernelradar.service
install:
	@if [ ! -f $(BIN) ]; then \
		echo "ERROR: $(BIN) not found. Run 'make' first (as user, not root)."; \
		exit 1; \
	fi
	@if [ ! -f $(BPF_DIR)/.output/privesc.bpf.o ]; then \
		echo "ERROR: BPF objects not built. Run 'make bpf' first."; \
		exit 1; \
	fi
	@echo "Installing kernelradar to $(PREFIX)..."
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/kernelradar
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)/bpf
	$(INSTALL) -m 0644 $(BPF_DIR)/.output/*.bpf.o          $(DESTDIR)$(LIBDIR)/bpf/
	$(INSTALL) -d $(DESTDIR)$(SYSTEMDDIR)
	$(INSTALL) -m 0644 contrib/systemd/kernelradar.service $(DESTDIR)$(SYSTEMDDIR)/
	@echo
	@echo "Done. To activate:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now kernelradar"
	@echo
	@echo "To watch alerts:"
	@echo "  journalctl -t kernelradar -f -o cat"

uninstall:
	-$(SYSTEMCTL) stop kernelradar 2>/dev/null
	-$(SYSTEMCTL) disable kernelradar 2>/dev/null
	rm -f $(DESTDIR)$(BINDIR)/kernelradar
	rm -rf $(DESTDIR)$(LIBDIR)
	rm -f $(DESTDIR)$(SYSTEMDDIR)/kernelradar.service
	-$(SYSTEMCTL) daemon-reload 2>/dev/null
	@echo "kernelradar uninstalled."

# ── systemd convenience targets ──────────────────────────────────────
service-start:
	$(SYSTEMCTL) start kernelradar

service-stop:
	$(SYSTEMCTL) stop kernelradar

service-restart:
	$(SYSTEMCTL) restart kernelradar

service-status:
	$(SYSTEMCTL) status kernelradar --no-pager

service-logs:
	journalctl -t kernelradar -f -o cat
