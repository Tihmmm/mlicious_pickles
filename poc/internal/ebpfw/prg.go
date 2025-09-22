package ebpfw

import (
	"bytes"
	"context"

	"github.com/Tihmmm/mlicious_pickles/internal/rules"
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
	WorkerFunc    func(e *EbpfPrg, ctx context.Context, analyzer rules.Analyzer)
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
		WorkerFunc:    DefaultWorkerFunc,
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

func (e *EbpfPrg) Worker(ctx context.Context, analyzer rules.Analyzer) {
	e.WorkerFunc(e, ctx, analyzer)
}
