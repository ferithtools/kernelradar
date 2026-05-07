# kernelradar - top-level orchestration Makefile
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
        service-status service-logs \
        release-tarball

all: bpf rust

# ── Build ────────────────────────────────────────────────────────────
bpf:
	$(MAKE) -C $(BPF_DIR)

# rust depends on bpf - the userspace `build.rs` hashes the .bpf.o
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
# Layout (separation of read-only BPF objects from writable runtime
# state - the systemd unit bind-mounts bpf/ read-only inside the
# unit's namespace, so an attacker with local root who writes to
# /var/lib/kernelradar/bpf on the real FS still cannot reach the
# daemon's view of those files):
#   /usr/local/bin/kernelradar
#   /var/lib/kernelradar/bpf/*.bpf.o          (root:root 0644, RO at runtime)
#   /var/lib/kernelradar/state/               (root:root 0750, RW; baseline.json)
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
	$(INSTALL) -d -m 0755 $(DESTDIR)$(LIBDIR)/bpf
	$(INSTALL) -m 0644 $(BPF_DIR)/.output/*.bpf.o          $(DESTDIR)$(LIBDIR)/bpf/
	$(INSTALL) -d -m 0750 $(DESTDIR)$(LIBDIR)/state
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

# ── Release tarball ──────────────────────────────────────────────────
# Produces dist/kernelradar-<version>-linux-x86_64.tar.gz that can be
# extracted on a target host and installed via the included install.sh.
# Run this on Linux (BPF objects are Linux-only).
RELEASE_VERSION := $(shell awk -F'"' \
    '/^version[[:space:]]*=[[:space:]]*"/{print $$2; exit}' \
    Cargo.toml 2>/dev/null || echo 0.0.0)
RELEASE_ARCH    := $(shell uname -m)
RELEASE_NAME    := kernelradar-$(RELEASE_VERSION)-linux-$(RELEASE_ARCH)
RELEASE_DIR     := dist/$(RELEASE_NAME)

release-tarball: all
	@echo "==> packaging $(RELEASE_NAME)"
	@rm -rf $(RELEASE_DIR) dist/$(RELEASE_NAME).tar.gz dist/$(RELEASE_NAME).tar.gz.sha256
	@mkdir -p $(RELEASE_DIR)/bin \
	          $(RELEASE_DIR)/lib/kernelradar/bpf \
	          $(RELEASE_DIR)/share/systemd \
	          $(RELEASE_DIR)/share/kernelradar
	@cp $(BIN)                                          $(RELEASE_DIR)/bin/kernelradar
	@cp $(BPF_DIR)/.output/*.bpf.o                      $(RELEASE_DIR)/lib/kernelradar/bpf/
	@cp contrib/systemd/kernelradar.service             $(RELEASE_DIR)/share/systemd/
	@$(BIN) config-cmd example                        > $(RELEASE_DIR)/share/kernelradar/config.toml.example
	@cp LICENSE README.md                               $(RELEASE_DIR)/
	@printf '%s\n' \
	  "#!/usr/bin/env bash" \
	  "# kernelradar $(RELEASE_VERSION) installer" \
	  "set -euo pipefail" \
	  "HERE=\"\$$(cd \"\$$(dirname \"\$${BASH_SOURCE[0]}\")\" && pwd)\"" \
	  "PREFIX=\"\$${PREFIX:-/usr/local}\"" \
	  "sudo install -m 0755 -D \"\$$HERE/bin/kernelradar\"          \"\$$PREFIX/bin/kernelradar\"" \
	  "sudo install -d -m 0755 /var/lib/kernelradar/bpf" \
	  "sudo install -m 0644 \"\$$HERE\"/lib/kernelradar/bpf/*.bpf.o /var/lib/kernelradar/bpf/" \
	  "sudo install -d -m 0750 /var/lib/kernelradar/state" \
	  "sudo install -m 0644 \"\$$HERE/share/systemd/kernelradar.service\" /etc/systemd/system/" \
	  "sudo install -d /etc/kernelradar" \
	  "[ -e /etc/kernelradar/config.toml ] || sudo cp \"\$$HERE/share/kernelradar/config.toml.example\" /etc/kernelradar/config.toml" \
	  "sudo systemctl daemon-reload" \
	  "echo 'Installed. Enable + start:'" \
	  "echo '  sudo systemctl enable --now kernelradar'" \
	  > $(RELEASE_DIR)/install.sh
	@chmod +x $(RELEASE_DIR)/install.sh
	@( cd $(RELEASE_DIR) && find . -type f ! -name SHA256SUMS \
	      | LC_ALL=C sort | xargs sha256sum > SHA256SUMS )
	@( cd dist && tar -czf $(RELEASE_NAME).tar.gz $(RELEASE_NAME) )
	@sha256sum dist/$(RELEASE_NAME).tar.gz | tee dist/$(RELEASE_NAME).tar.gz.sha256
	@echo "==> dist/$(RELEASE_NAME).tar.gz ready"
	@ls -la dist/$(RELEASE_NAME).tar.gz
