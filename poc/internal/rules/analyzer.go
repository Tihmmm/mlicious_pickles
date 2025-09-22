package rules

import (
	"strings"

	"github.com/Tihmmm/mlicious_pickles/internal/util"
	"github.com/hillu/go-yara/v4"
)

var DefaultYaraAnalyzerFunc = func(a *YaraAnalyzer, data []byte) (*ScanResult, error) {
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
