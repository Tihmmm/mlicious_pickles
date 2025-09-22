package rules

import (
	"os"

	"github.com/hillu/go-yara/v4"
)

type Analyzer interface {
	Analyze(data []byte) (*ScanResult, error)
	Close() error
}

type YaraAnalyzer struct {
	Scanner      *yara.Scanner
	Rules        *yara.Rules
	AnalyzerFunc func(a *YaraAnalyzer, data []byte) (*ScanResult, error)
}

type ScanResult struct {
	Matches          []string
	DangerousGlobals []string
}

func NewYaraAnalyzer(rulesPath string) (*YaraAnalyzer, error) {
	rules, err := compileYARARules(rulesPath)
	if err != nil {
		return nil, err
	}

	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return nil, err
	}

	return &YaraAnalyzer{
		Scanner:      scanner,
		Rules:        rules,
		AnalyzerFunc: DefaultYaraAnalyzerFunc,
	}, nil
}

func (a *YaraAnalyzer) Analyze(data []byte) (*ScanResult, error) {
	return a.AnalyzerFunc(a, data)
}

func (a *YaraAnalyzer) Close() error {
	a.Rules.Destroy()

	return nil
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
