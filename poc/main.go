package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Tihmmm/mlicious_pickles/internal/ebpfw"
	"github.com/Tihmmm/mlicious_pickles/internal/rules"
	"github.com/cilium/ebpf/rlimit"
)

var rulesPath = flag.String("rules", "rules/pickle.yar", "Path to YARA rules")

func main() {
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v\n", err)
	}

	prog, err := ebpfw.NewEbpfPrg()
	if err != nil {
		log.Fatalf("ebpf program: %v", err)
	}
	objs := prog.Objects
	defer prog.Close()

	prog.AttachTracepoint("syscalls", "sys_enter_openat", objs.TpEnterOpenat)
	prog.AttachTracepoint("syscalls", "sys_exit_openat", objs.TpExitOpenat)
	prog.AttachTracepoint("syscalls", "sys_enter_read", objs.TpEnterRead)
	prog.AttachTracepoint("syscalls", "sys_exit_read", objs.TpExitRead)
	prog.AttachTracepoint("syscalls", "sys_enter_close", objs.TpEnterClose)
	prog.AttachTracepoint("syscalls", "sys_exit_close", objs.TpExitClose2)

	analyzer, err := rules.NewYaraAnalyzer(*rulesPath)
	if err != nil {
		log.Fatalf("yara init: %v", err)
	}
	defer analyzer.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("MLiciousPickles started.\n")
	prog.Worker(ctx, analyzer)
}
