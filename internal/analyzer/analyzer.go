// Package analyzer implements behavioral analysis of syscall events collected
// during pickle deserialization. It applies a set of detection rules against
// the event stream and produces a verdict.
package analyzer

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Tihmmm/mlicious_pickles/internal/events"
)

// Severity levels for detection rules
type Severity int

const (
	SeverityNone     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

func (s Severity) String() string {
	switch s {
	case SeverityNone:
		return "NONE"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// Verdict is the overall assessment of a pickle file
type Verdict int

const (
	VerdictSafe       Verdict = 0
	VerdictSuspicious Verdict = 1
	VerdictMalicious  Verdict = 2
)

func (v Verdict) String() string {
	switch v {
	case VerdictSafe:
		return "SAFE"
	case VerdictSuspicious:
		return "SUSPICIOUS"
	case VerdictMalicious:
		return "MALICIOUS"
	default:
		return "UNKNOWN"
	}
}

// Finding is a single detection rule match
type Finding struct {
	Rule     string
	Severity Severity
	Detail   string
}

// Report is the complete analysis output
type Report struct {
	Verdict    Verdict
	Findings   []Finding
	EventCount int
}

// sensitiveFiles are paths that should not be accessed during deserialization
var sensitiveFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/ssh/",
	"/.ssh/",
	"/id_rsa",
	"/id_ed25519",
	"/authorized_keys",
	"/etc/hosts",
	"/proc/self/",
	"/etc/crontab",
	"/var/spool/cron",
}

// shells are executables that indicate shell access
var shells = []string{
	"/bin/sh",
	"/bin/bash",
	"/bin/zsh",
	"/bin/dash",
	"/usr/bin/sh",
	"/usr/bin/bash",
	"/usr/bin/zsh",
}

// Analyzer processes events and applies detection rules
type Analyzer struct {
	mu       sync.Mutex
	findings []Finding
	count    int

	// Track state across events for correlation
	sawSocket  bool
	sawConnect bool
	sawExecve  bool
}

// New creates a new Analyzer
func New() *Analyzer {
	return &Analyzer{}
}

// ProcessExecve analyzes an execve event
func (a *Analyzer) ProcessExecve(e *events.ExecveEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++
	a.sawExecve = true

	filename := e.GetFilename()
	args := e.GetArgs()

	// Any execve during deserialization is critical - pickles SHOULD NOT spawn processes
	detail := fmt.Sprintf("executed %s %s", filename, strings.Join(args, " "))
	a.addFinding("process_execution", SeverityCritical, detail)

	// Check for shell execution specifically
	for _, sh := range shells {
		if filename == sh {
			a.addFinding("shell_execution", SeverityCritical,
				fmt.Sprintf("shell invoked: %s", detail))
			break
		}
	}

	// Reverse shell detection: socket + connect + shell exec
	if a.sawSocket && a.sawConnect {
		for _, sh := range shells {
			if filename == sh {
				a.addFinding("reverse_shell", SeverityCritical,
					"socket + connect + shell execution pattern detected")
				break
			}
		}
	}
}

// ProcessOpenat analyzes an openat event
func (a *Analyzer) ProcessOpenat(e *events.OpenatEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++

	filename := e.GetFilename()

	for _, sensitive := range sensitiveFiles {
		if strings.Contains(filename, sensitive) {
			a.addFinding("sensitive_file_access", SeverityHigh,
				fmt.Sprintf("accessed sensitive file: %s", filename))
			return
		}
	}
}

// ProcessConnect analyzes a connect event
func (a *Analyzer) ProcessConnect(e *events.ConnectEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++
	a.sawConnect = true

	ip := e.IP()
	port := e.PortNumber()

	if ip == nil {
		// Non-IP connection (e.g., AF_UNIX) is lower concern
		if e.AddrFamily != 1 { // AF_UNIX
			a.addFinding("network_connection", SeverityHigh,
				fmt.Sprintf("connect to unknown address family %d", e.AddrFamily))
		}
		return
	}

	// Connections to external IPs are sus
	if !isLocalIP(ip) {
		a.addFinding("external_connection", SeverityHigh,
			fmt.Sprintf("connect to external address %s:%d", ip, port))
	} else {
		a.addFinding("local_connection", SeverityMedium,
			fmt.Sprintf("connect to local address %s:%d", ip, port))
	}
}

// ProcessSocket analyzes a socket event
func (a *Analyzer) ProcessSocket(e *events.SocketEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++
	a.sawSocket = true

	// AF_INET or AF_INET6 socket creation is notable
	if e.Domain == 2 || e.Domain == 10 {
		a.addFinding("socket_creation", SeverityLow,
			fmt.Sprintf("created network socket (domain=%d type=%d proto=%d)",
				e.Domain, e.Type, e.Protocol))
	}
}

// ProcessWrite analyzes a write event
func (a *Analyzer) ProcessWrite(e *events.WriteEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++

	// Writes to non-stdio file descriptors are suspicious during deserialization
	// stdin=0, stdout=1, stderr=2
	if e.FD > 2 {
		a.addFinding("file_write", SeverityMedium,
			fmt.Sprintf("write to fd=%d (%d bytes)", e.FD, e.Count))
	}
}

// ProcessUnlinkat analyzes an unlinkat event
func (a *Analyzer) ProcessUnlinkat(e *events.UnlinkatEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++

	filename := e.GetFilename()
	a.addFinding("file_deletion", SeverityMedium,
		fmt.Sprintf("deleted file: %s", filename))
}

// ProcessClone analyzes a clone event
func (a *Analyzer) ProcessClone(e *events.CloneEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++

	// CLONE_THREAD (0x00010000) indicates thread creation, which is less concerning.
	// New process creation is more suspicious though
	if e.CloneFlags&0x00010000 == 0 {
		a.addFinding("process_creation", SeverityMedium,
			fmt.Sprintf("clone with flags=0x%x", e.CloneFlags))
	}
}

// Report generates the final analysis report.
func (a *Analyzer) Report() Report {
	a.mu.Lock()
	defer a.mu.Unlock()

	verdict := VerdictSafe
	for _, f := range a.findings {
		switch {
		case f.Severity >= SeverityHigh && verdict < VerdictMalicious:
			verdict = VerdictMalicious
		case f.Severity >= SeverityLow && verdict < VerdictSuspicious:
			verdict = VerdictSuspicious
		}
	}

	return Report{
		Verdict:    verdict,
		Findings:   append([]Finding(nil), a.findings...),
		EventCount: a.count,
	}
}

func (a *Analyzer) addFinding(rule string, severity Severity, detail string) {
	a.findings = append(a.findings, Finding{
		Rule:     rule,
		Severity: severity,
		Detail:   detail,
	})
}

var localIps = []net.IPNet{
	{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
	{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
}

func isLocalIP(ip net.IP) bool {
	for _, n := range localIps {
		if n.Contains(ip) {
			return true
		}
	}

	return ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
