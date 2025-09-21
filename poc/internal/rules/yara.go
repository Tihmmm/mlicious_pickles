package rules

import (
	"os"
	"strings"

	"github.com/Tihmmm/mlicious_pickles/internal/util"
	"github.com/hillu/go-yara/v4"
)

type Analyzer interface {
	Analyze(data []byte) (*ScanResult, error)
	Close() error
}

type YaraAnalyzer struct {
	Scanner *yara.Scanner
	Rules   *yara.Rules
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
		Scanner: scanner,
		Rules:   rules,
	}, nil
}

func (a *YaraAnalyzer) Analyze(data []byte) (*ScanResult, error) {
	var res ScanResult
	cb := yara.MatchRules{}
	err := a.Scanner.SetCallback(&cb).ScanMem(data)
	if err != nil {
		return nil, err
	}
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
			mod, ok1, off1 := util.ReadToNL(data, j)
			if !ok1 {
				continue
			}
			nam, ok2, _ := util.ReadToNL(data, off1)
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

	return &res, nil
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
