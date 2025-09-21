//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -output-dir internal/ebpfw -go-package ebpfw -cc clang -cflags "-I. -O2 -g" PickleTrace bpf/pickle_trace.bpf.c -- -I.

package main
