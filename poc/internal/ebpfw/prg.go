package ebpfw

import (
	"bytes"
	"context"

	"github.com/Tihmmm/mlicious_pickles/internal/rules"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

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

	return &EbpfPrg{
		Objects:       &objs,
		Links:         []link.Link{},
		RingBufReader: rd,
		Streams:       map[string]*streamBuf{},
		WorkerFunc:    DefaultWorkerFunc,
	}, nil
}

func AttachTracepoint(e *EbpfPrg, cat, name string, prog *ebpf.Program) error {
	l, err := link.Tracepoint(cat, name, prog, nil)
	if err != nil {
		return err
	}

	e.Links = append(e.Links, l)

	return nil
}

func Close(e *EbpfPrg) error {
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

func Worker(e *EbpfPrg, ctx context.Context, analyzer rules.Analyzer) {
	e.WorkerFunc(e, ctx, analyzer)
}
