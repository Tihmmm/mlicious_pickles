// Command mliciouspickles is an eBPF-based dynamic pickle scanner.
// It monitors syscalls during Python pickle deserialization and reports whether the pickle exhibits malicious behavior.
//
// Usage:
//
//	sudo mliciouspickles [-timeout 30s] [-python python3] <pickle-file>
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Tihmmm/mlicious_pickles/internal/analyzer"
	"github.com/Tihmmm/mlicious_pickles/internal/scanner"
)

func main() {
	timeout := flag.Duration("timeout", 30*time.Second, "maximum time for deserialization")
	pythonBin := flag.String("python", "python3", "python interpreter path")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <pickle-file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "MLiciousPickles - eBPF-based dynamic pickle scanner.\n")
		fmt.Fprintf(os.Stderr, "Monitors syscalls during pickle deserialization to detect malicious behavior.\n")
		fmt.Fprintf(os.Stderr, "Requires root privileges (CAP_BPF + CAP_PERFMON at minimum).\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	picklePath := flag.Arg(0)
	if _, err := os.Stat(picklePath); err != nil {
		log.Fatalf("pickle file: %v", err)
	}

	if os.Geteuid() != 0 {
		log.Fatal("this program requires root privileges (or CAP_BPF + CAP_PERFMON)")
	}

	cfg := scanner.DefaultConfig()
	cfg.PicklePath = picklePath
	cfg.Timeout = *timeout
	cfg.PythonBin = *pythonBin

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	s := scanner.New(cfg)
	report, err := s.Scan(ctx)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	// TODO: different output formats?
	printReport(report)

	if report.Verdict == analyzer.VerdictMalicious {
		os.Exit(1)
	}
}

func printReport(r *analyzer.Report) {
	sep := strings.Repeat("-", 60)

	fmt.Println(sep)
	fmt.Printf("  Verdict:  %s\n", r.Verdict)
	fmt.Printf("  Events:   %d captured\n", r.EventCount)
	fmt.Printf("  Findings: %d\n", len(r.Findings))
	fmt.Println(sep)

	if len(r.Findings) == 0 {
		fmt.Println("  No suspicious activity detected.")
		fmt.Println(sep)
		return
	}

	for i, f := range r.Findings {
		fmt.Printf("  [%d] %-10s %-24s %s\n", i+1, f.Severity, f.Rule, f.Detail)
	}
	fmt.Println(sep)
}
