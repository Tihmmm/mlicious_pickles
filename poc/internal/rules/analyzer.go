package rules

type Analyzer interface {
	Analyze(data []byte) (*ScanResult, error)
	Close() error
}
