# MLiciousPickles

eBPF-based dynamic pickle scanner that monitors syscall behavior during Python pickle deserialization to detect malicious activity at the kernel level.

## How It Works

1. Loads eBPF tracepoint programs into the kernel
2. Spawns a Python process to deserialize the target pickle file
3. eBPF programs intercept syscalls (execve, openat, connect, socket, write, unlinkat, clone) from the target process and its children
4. Events flow to userspace via ring buffer
5. A behavioral analyzer examines the event stream and produces a verdict: **SAFE**, **SUSPICIOUS**, or **MALICIOUS**

## Requirements

- **OS**: Ubuntu 24.04.4 LTS (kernel 6.8+ with BTF support)
- **Go**: 1.26+ (though 1.21+ should also work)
- **clang**: for BPF compilation
- **libbpf-dev**: BPF helper headers
- **linux-tools-$(uname -r)**: bpftool (for vmlinux.h generation)
- **python3**: target deserializer

### Install build dependencies (Ubuntu 24.04)

```bash
sudo apt install clang libbpf-dev linux-tools-$(uname -r) linux-tools-common python3
```

## Build

```bash
# Install Go tooling and tidy modules
make deps

# Generate vmlinux.h from kernel BTF (first time / after kernel update)
make vmlinux

# Compile eBPF programs + Go bindings + build binary
make build
```

The binary is written to `bin/mliciouspickles`.

## Usage

```bash
# Scan a pickle file (requires root)
sudo ./bin/mliciouspickles path/to/file.pkl

# With custom timeout and Python path
sudo ./bin/mliciouspickles -timeout 60s -python python3.12 file.pkl
```

### Exit codes

- `0` - pickle is safe or suspicious
- `1` - pickle is malicious
- `2` - usage error

## Architecture

See [docs/HLD.md](docs/HLD.md) for the full high-level design.
