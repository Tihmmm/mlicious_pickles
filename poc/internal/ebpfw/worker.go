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
	"github.com/cilium/ebpf/ringbuf"
)

const (
	maxComm        = 16
	maxPath        = 256
	maxChunk       = 512
	maxBufSize int = 8 << 20
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

var DefaultWorkerFunc = func(e *EbpfPrg, ctx context.Context, analyzer rules.Analyzer) {
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
		} else if sb.buf.Len() >= maxBufSize {
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
