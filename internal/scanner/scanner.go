// Package scanner orchestrates the pickle scanning workflow:
// load eBPF -> spawn Python process -> collect events -> analyze -> report.
package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/Tihmmm/mlicious_pickles/internal/analyzer"
	"github.com/Tihmmm/mlicious_pickles/internal/bpf"
	"github.com/Tihmmm/mlicious_pickles/internal/events"
)

// Config holds scanner configuration
type Config struct {
	PicklePath   string
	Timeout      time.Duration
	DrainTimeout time.Duration
	PythonBin    string
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Timeout:      30 * time.Second,
		DrainTimeout: 500 * time.Millisecond,
		PythonBin:    "python3",
	}
}

// Scanner is the top-level pickle scanning engine
type Scanner struct {
	cfg Config
}

// New creates a Scanner with the given configuration
func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Scan runs the full scanning pipeline and returns an analysis report
func (s *Scanner) Scan(ctx context.Context) (*analyzer.Report, error) {
	// 1. Load eBPF programs
	loader, err := bpf.Load()
	if err != nil {
		return nil, fmt.Errorf("loading eBPF: %w", err)
	}
	defer loader.Close()

	// 2. Attach tracepoints and open ring buffer
	reader, err := loader.Attach()
	if err != nil {
		return nil, fmt.Errorf("attaching eBPF: %w", err)
	}

	// 3. Spawn the Python deserialization process
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	script := fmt.Sprintf(
		"import pickle, sys; pickle.loads(open(sys.argv[1], 'rb').read())",
	)
	cmd := exec.CommandContext(ctx, s.cfg.PythonBin, "-c", script, s.cfg.PicklePath)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting python process: %w", err)
	}

	pid := uint32(cmd.Process.Pid)
	log.Printf("spawned %s (PID %d) to deserialize %s", s.cfg.PythonBin, pid, s.cfg.PicklePath)

	// 4. Register the PID for eBPF tracking
	if err := loader.AddPID(pid); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("registering PID: %w", err)
	}

	// 5. Collect events in background
	az := analyzer.New()
	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		collectEvents(reader, az)
	}()

	// 6. Wait for the process to finish
	procErr := cmd.Wait()
	if procErr != nil {
		// The process may exit non-zero due to malicious code or errors
		log.Printf("python process exited: %v", procErr)
		if stderr.Len() > 0 {
			log.Printf("python stderr: %s", stderr.String())
		}
	}

	// 7. Drain remaining events from the ring buffer
	time.Sleep(s.cfg.DrainTimeout)
	reader.Close() // unblocks the collectEvents goroutine
	<-eventsDone

	// 8. Generate report.
	report := az.Report()
	return &report, nil
}

// collectEvents reads from the ring buffer and dispatches events to the analyzer
func collectEvents(reader *ringbuf.Reader, az *analyzer.Analyzer) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading ring buffer: %v", err)
			continue
		}

		if len(record.RawSample) < 24 { // sizeof(event_header)
			continue
		}

		// Peek at the event type from the header
		eventType := events.EventType(binary.LittleEndian.Uint32(record.RawSample[16:20]))

		// https://www.youtube.com/watch?v=4K8IEzXnMYk
		switch eventType {
		case events.EventExecve:
			var e events.ExecveEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding execve event: %v", err)
				continue
			}
			az.ProcessExecve(&e)

		case events.EventOpenat:
			var e events.OpenatEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding openat event: %v", err)
				continue
			}
			az.ProcessOpenat(&e)

		case events.EventConnect:
			var e events.ConnectEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding connect event: %v", err)
				continue
			}
			az.ProcessConnect(&e)

		case events.EventSocket:
			var e events.SocketEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding socket event: %v", err)
				continue
			}
			az.ProcessSocket(&e)

		case events.EventWrite:
			var e events.WriteEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding write event: %v", err)
				continue
			}
			az.ProcessWrite(&e)

		case events.EventUnlinkat:
			var e events.UnlinkatEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding unlinkat event: %v", err)
				continue
			}
			az.ProcessUnlinkat(&e)

		case events.EventClone:
			var e events.CloneEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decoding clone event: %v", err)
				continue
			}
			az.ProcessClone(&e)

		default:
			log.Printf("unknown event type: %d", eventType)
		}
	}
}
