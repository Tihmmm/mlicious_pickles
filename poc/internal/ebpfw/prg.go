package ebpfw

import (
	"bytes"
	"context"
	"errors"

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

func (e *EbpfPrg) Close() error {
	if e == nil {
		return nil
	}

	var err error
	if e.Objects != nil {
		err = errors.Join(err, e.Objects.Close())
		e.Objects = nil
	}

	if e.Links != nil {
		for _, l := range e.Links {
			err = errors.Join(err, l.Close())
		}
		e.Links = nil
	}

	if e.RingBufReader != nil {
		err = errors.Join(err, e.RingBufReader.Close())
	}

	return nil
}

func Worker(e *EbpfPrg, ctx context.Context, analyzer rules.Analyzer) {
	e.WorkerFunc(e, ctx, analyzer)
}
