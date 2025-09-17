//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-I. -O2 -g" PickleTrace bpf/pickle_trace.bpf.c -- -I.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hillu/go-yara/v4"
)

const (
	maxComm  = 16
	maxPath  = 256
	maxChunk = 512
)

type event struct {
	Pid     uint32
	Fd      int32
	Offset  uint64
	DataLen uint32
	Flags   uint32
	Comm    [maxComm]byte
	Path    [maxPath]byte
	Data    [maxChunk]byte
}

type streamBuf struct {
	path    string
	buf     *bytes.Buffer
	hash    [32]byte
	lastOff uint64
}

func main() {
	var (
		yaraPath   = flag.String("yara", "rules/pickle.yar", "Path to YARA rules")
		pythonOnly = flag.Bool("python-only", true, "Only track processes with 'python' in comm")
		maxSize    = flag.Int("max-bytes", 8<<20, "Max bytes to buffer per fd before scanning")
	)
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v\n", err)
	}

	var objs PickleTraceObjects
	if err := LoadPickleTraceObjects(&objs, nil); err != nil {
		log.Fatalf("load bpf: %v\n", err)
	}
	defer objs.Close()

	var links []link.Link
	attach := func(cat, name string, prog *ebpf.Program) {
		l, err := link.Tracepoint(cat, name, prog, nil)
		if err != nil {
			log.Fatalf("attach %s:%s: %v\n", cat, name, err)
		}
		links = append(links, l)
	}
	attach("syscalls", "sys_enter_openat", objs.TpEnterOpenat)
	attach("syscalls", "sys_exit_openat", objs.TpExitOpenat)
	attach("syscalls", "sys_enter_read", objs.TpEnterRead)
	attach("syscalls", "sys_exit_read", objs.TpExitRead)
	attach("syscalls", "sys_enter_close", objs.TpEnterClose)
	attach("syscalls", "sys_exit_close", objs.TpExitClose2)
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v\n", err)
	}
	defer rd.Close()

	rules, err := compileYARARules(*yaraPath)
	if err != nil {
		log.Fatalf("yara: %v\n", err)
	}
	defer rules.Destroy()
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		log.Fatalf("yara scanner: %v\n", err)
	}

	streams := map[string]*streamBuf{}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("MLiciousPickles started.\n")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var ev event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		comm := cstr(ev.Comm[:])
		if *pythonOnly && !strings.Contains(comm, "python") {
			continue
		}
		path := cstr(ev.Path[:])
		key := fmt.Sprintf("%d:%d", ev.Pid, ev.Fd)
		sb := streams[key]
		if sb == nil {
			sb = &streamBuf{path: path, buf: &bytes.Buffer{}}
			streams[key] = sb
		}

		if ev.DataLen > 0 && int(ev.DataLen) <= len(ev.Data) {
			sb.buf.Write(ev.Data[:ev.DataLen])
			sb.lastOff = ev.Offset + uint64(ev.DataLen)
		}

		shouldScan := false
		reason := ""
		if ev.Flags&1 == 1 {
			shouldScan = true
			reason = "fd_close"
		} else if sb.buf.Len() >= *maxSize {
			shouldScan = true
			reason = "size_threshold"
		} else if sb.buf.Len() >= 2 {
			b := sb.buf.Bytes()
			if b[0] == 0x80 {
				shouldScan = true
				reason = "pickle_magic"
			}
		}

		if shouldScan {
			data := sb.buf.Bytes()
			findings := analyze(data, scanner)

			if len(findings.Matches) > 0 || len(findings.DangerousGlobals) > 0 {
				out := map[string]any{
					"pid":       ev.Pid,
					"fd":        ev.Fd,
					"comm":      comm,
					"path":      path,
					"reason":    reason,
					"size":      len(data),
					"yara":      findings.Matches,
					"globals":   findings.DangerousGlobals,
					"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
				}

				enc := json.NewEncoder(os.Stdout)
				enc.SetEscapeHTML(false)
				_ = enc.Encode(out)
			}

			delete(streams, key)
		}
	}
}

func compileYARARules(path string) (*yara.Rules, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := c.AddFile(f, ""); err != nil {
		return nil, err
	}

	return c.GetRules()
}

type scanResult struct {
	Matches          []string
	DangerousGlobals []string
}

func analyze(data []byte, sc *yara.Scanner) scanResult {
	res := scanResult{}
	cb := yara.MatchRules{}
	_ = sc.SetCallback(&cb).ScanMem(data)
	for _, m := range cb {
		res.Matches = append(res.Matches, m.Rule)
	}

	suspTargets := []string{
		"builtins.eval", "builtins.exec", "os.system", "posix.system", "subprocess.Popen",
	}

	found := map[string]struct{}{}
	for i := 0; i+1 < len(data); i++ {
		if data[i] == 'c' {
			j := i + 1
			mod, ok1, off1 := readToNL(data, j)
			if !ok1 {
				continue
			}
			nam, ok2, _ := readToNL(data, off1)
			if !ok2 {
				continue
			}
			full := mod + "." + nam
			for _, bad := range suspTargets {
				if strings.EqualFold(full, bad) {
					found[full] = struct{}{}
				}
			}
		}
	}

	for k := range found {
		res.DangerousGlobals = append(res.DangerousGlobals, k)
	}

	return res
}

func readToNL(b []byte, start int) (string, bool, int) {
	for k := start; k < len(b); k++ {
		if b[k] == '\n' {
			return string(b[start:k]), true, k + 1
		}
	}

	return "", false, start
}

func cstr(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		i = len(b)
	}

	return string(b[:i])
}
