package collector

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessInfo struct {
	PID         int32   `json:"pid"`
	Name        string  `json:"name"`
	Executable  string  `json:"executable,omitempty"`
	CPU         float64 `json:"cpu_percent"`
	Memory      float32 `json:"memory_percent"`
	CommandLine string  `json:"command_line,omitempty"`
	ParentPID   int32   `json:"parent_pid,omitempty"`
}

type SuspiciousProcess struct {
	PID      int32  `json:"pid"`
	Name     string `json:"name"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
}

type ProcessCollector struct {
	mu            sync.Mutex
	previous      map[int32]ProcessInfo
	blacklist     []string
	whitelist     map[string]bool
	alertChan     chan SuspiciousProcess
	scanInterval  time.Duration
}

func NewProcessCollector(whitelist, blacklist []string, alertChan chan SuspiciousProcess) *ProcessCollector {
	wl := make(map[string]bool, len(whitelist))
	for _, p := range whitelist {
		wl[strings.ToLower(p)] = true
	}
	return &ProcessCollector{
		previous:     make(map[int32]ProcessInfo),
		blacklist:    blacklist,
		whitelist:    wl,
		alertChan:    alertChan,
		scanInterval: 30 * time.Second,
	}
}

func (pc *ProcessCollector) Start(ctx context.Context) {
	ticker := time.NewTicker(pc.scanInterval)
	defer ticker.Stop()

	pc.scanOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pc.scanOnce()
		}
	}
}

func (pc *ProcessCollector) scanOnce() {
	procs, err := pc.getRunningProcesses()
	if err != nil {
		return
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	newProcs := pc.detectNewProcessesLocked(procs)
	suspicious := pc.detectSuspiciousProcessesLocked(newProcs)

	pc.previous = make(map[int32]ProcessInfo, len(procs))
	for _, p := range procs {
		pc.previous[p.PID] = p
	}

	for _, s := range suspicious {
		select {
		case pc.alertChan <- s:
		default:
		}
	}
}

func (pc *ProcessCollector) getRunningProcesses() ([]ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}

	result := make([]ProcessInfo, 0, len(procs))
	for _, p := range procs {
		info := ProcessInfo{PID: p.Pid}

		if name, err := p.Name(); err == nil {
			info.Name = name
		}
		if exe, err := p.Exe(); err == nil {
			info.Executable = exe
		}
		if cpuP, err := p.CPUPercent(); err == nil {
			info.CPU = cpuP
		}
		if mem, err := p.MemoryPercent(); err == nil {
			info.Memory = mem
		}
		if cmdline, err := p.Cmdline(); err == nil {
			info.CommandLine = cmdline
		}
		if ppid, err := p.Ppid(); err == nil {
			info.ParentPID = ppid
		}

		result = append(result, info)
	}
	return result, nil
}

func (pc *ProcessCollector) detectNewProcessesLocked(current []ProcessInfo) []ProcessInfo {
	var newProcs []ProcessInfo
	for _, p := range current {
		if _, exists := pc.previous[p.PID]; !exists {
			newProcs = append(newProcs, p)
		}
	}
	return newProcs
}

func (pc *ProcessCollector) detectSuspiciousProcessesLocked(procs []ProcessInfo) []SuspiciousProcess {
	var suspicious []SuspiciousProcess

	for _, p := range procs {
		name := strings.ToLower(p.Name)
		if pc.whitelist[name] {
			continue
		}

		if runtime.GOOS == "windows" {
			exe := strings.ToLower(p.Executable)
			if exe != "" {
				if !strings.HasPrefix(exe, "c:\\windows\\") && !strings.HasPrefix(exe, "c:\\program files") {
					if !isDigitallySigned(p.Executable) {
						suspicious = append(suspicious, SuspiciousProcess{
							PID:      p.PID,
							Name:     p.Name,
							Reason:   "Unsigned binary running from non-standard location",
							Severity: "medium",
						})
						continue
					}
				}
			}
		}

		for _, bl := range pc.blacklist {
			if strings.Contains(name, strings.ToLower(bl)) {
				suspicious = append(suspicious, SuspiciousProcess{
					PID:      p.PID,
					Name:     p.Name,
					Reason:   fmt.Sprintf("Matches blacklisted process: %s", bl),
					Severity: "high",
				})
				continue
			}
		}

		if p.CPU > 90.0 && p.Memory > 50.0 {
			suspicious = append(suspicious, SuspiciousProcess{
				PID:      p.PID,
				Name:     p.Name,
				Reason:   fmt.Sprintf("High resource usage: CPU=%.1f%%, Memory=%.1f%%", p.CPU, p.Memory),
				Severity: "low",
			})
		}
	}

	return suspicious
}

func isDigitallySigned(path string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return false
}

func (pc *ProcessCollector) DetectNewProcesses() ([]ProcessInfo, error) {
	procs, err := pc.getRunningProcesses()
	if err != nil {
		return nil, err
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	newProcs := pc.detectNewProcessesLocked(procs)

	pc.previous = make(map[int32]ProcessInfo, len(procs))
	for _, p := range procs {
		pc.previous[p.PID] = p
	}

	return newProcs, nil
}

func (pc *ProcessCollector) DetectSuspiciousProcesses() ([]SuspiciousProcess, error) {
	procs, err := pc.getRunningProcesses()
	if err != nil {
		return nil, err
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.detectSuspiciousProcessesLocked(procs), nil
}
