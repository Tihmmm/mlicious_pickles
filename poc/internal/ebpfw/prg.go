package ebpfw

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Tihmmm/mlicious_pickles/internal/rules"
	"github.com/Tihmmm/mlicious_pickles/internal/util"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Prg interface {
	AttachTracepoint(cat, name string, prog *ebpf.Program) error
	Close() error
	Worker(ctx context.Context, analyzer rules.Analyzer)
}

type EbpfPrg struct {
	Objects       *PickleTraceObjects
	Links         []link.Link
	RingBufReader *ringbuf.Reader
	Streams       map[string]*streamBuf
}

type streamBuf struct {
	path    string
	buf     *bytes.Buffer
	hash    [32]byte
	lastOff uint64
}

func NewEbpfPrg() (*EbpfPrg, error) {
	var objs PickleTraceObjects
	if err := LoadPickleTraceObjects(&objs, nil); err != nil {
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, err
	}

	streams := map[string]*streamBuf{}

	return &EbpfPrg{
		Objects:       &objs,
		Links:         []link.Link{},
		RingBufReader: rd,
		Streams:       streams,
	}, nil
}

func (e *EbpfPrg) AttachTracepoint(cat, name string, prog *ebpf.Program) error {
	l, err := link.Tracepoint(cat, name, prog, nil)
	if err != nil {
		return err
	}

	e.Links = append(e.Links, l)

	return nil
}

func (e *EbpfPrg) Close() error {
	if err := e.Objects.Close(); err != nil {
		return err
	}

	for _, l := range e.Links {
		if err := l.Close(); err != nil {
			return err
		}
	}

	if err := e.RingBufReader.Close(); err != nil {
		return err
	}

	return nil
}

const (
	maxComm      = 16
	maxPath      = 256
	maxChunk     = 512
	maxSize  int = 8 << 20
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

func (e *EbpfPrg) Worker(ctx context.Context, analyzer rules.Analyzer) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := e.RingBufReader.Read()
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

		comm := util.Cstr(ev.Comm[:])
		if !strings.Contains(comm, "python") {
			continue
		}

		path := util.Cstr(ev.Path[:])
		key := fmt.Sprintf("%d:%d", ev.Pid, ev.Fd)
		sb := e.Streams[key]
		if sb == nil {
			sb = &streamBuf{path: path, buf: &bytes.Buffer{}}
			e.Streams[key] = sb
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
		} else if sb.buf.Len() >= maxSize {
			shouldScan = true
			reason = "size_threshold"
		} else if sb.buf.Len() >= 2 {
			b := sb.buf.Bytes()
			if b[0] == 0x80 {
				shouldScan = true
				reason = "pickle_magic"
			}
		}

		if shouldScan && analyzer != nil {
			data := sb.buf.Bytes()
			findings, err := analyzer.Analyze(data)
			if err != nil {
				log.Printf("analysis failed for pid: %d. error: %v\n", ev.Pid, err)
				continue
			}

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

			delete(e.Streams, key)
		}
	}
}
