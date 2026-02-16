# MLiciousPickles - eBPF-based dynamic pickle scanner
# Target OS: Ubuntu 24.04.4 LTS (kernel 6.8+)

BINARY   := mliciouspickles
BINDIR   := bin
CMD      := ./cmd/mliciouspickles

VMLINUX  := internal/bpf/headers/vmlinux.h
BPF_SRC  := internal/bpf/c/scanner.c

CLANG    ?= clang
BPFTOOL  ?= bpftool
GO       ?= go

.PHONY: all build generate vmlinux clean deps check-deps

all: build

check-deps:
	@command -v $(CLANG)   >/dev/null 2>&1 || { echo "clang is required:   sudo apt install clang";          exit 1; }
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "bpftool is required: sudo apt install linux-tools-$$(uname -r)"; exit 1; }
	@command -v $(GO)      >/dev/null 2>&1 || { echo "go is required:      see https://go.dev/dl/";          exit 1; }

deps: check-deps
	$(GO) mod tidy
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

vmlinux: $(VMLINUX)

$(VMLINUX):
	@echo "==> Generating vmlinux.h from kernel BTF"
	@test -f /sys/kernel/btf/vmlinux || { echo "BTF not available - is CONFIG_DEBUG_INFO_BTF=y?"; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "==> vmlinux.h written to $@"

generate: $(VMLINUX) check-deps
	@echo "==> Running bpf2go code generation"
	cd internal/bpf && $(GO) generate ./...
	@echo "==> Generated BPF objects and Go bindings"

build: generate
	@mkdir -p $(BINDIR)
	@echo "==> Building $(BINARY)"
	CGO_ENABLED=0 $(GO) build -o $(BINDIR)/$(BINARY) $(CMD)
	@echo "==> $(BINDIR)/$(BINARY) built successfully"

clean:
	rm -rf $(BINDIR)
	rm -f internal/bpf/scanner_bpf*.go internal/bpf/scanner_bpf*.o
	@echo "==> Cleaned build artifacts"
