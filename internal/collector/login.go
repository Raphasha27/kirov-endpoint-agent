package collector

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type LoginEvent struct {
	Username  string    `json:"username"`
	SourceIP  string    `json:"source_ip"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Type      string    `json:"type"`
}

type BruteForceAlert struct {
	SourceIP  string    `json:"source_ip"`
	Count     int       `json:"count"`
	Window    string    `json:"window"`
	Timestamp time.Time `json:"timestamp"`
}

type LoginCollector struct {
	mu              sync.Mutex
	recentEvents    []LoginEvent
	alertChan       chan<- BruteForceAlert
	scanInterval    time.Duration
	bruteThreshold  int
	bruteWindow     time.Duration
}

func NewLoginCollector(alertChan chan<- BruteForceAlert) *LoginCollector {
	return &LoginCollector{
		alertChan:      alertChan,
		scanInterval:   15 * time.Second,
		bruteThreshold: 5,
		bruteWindow:    1 * time.Minute,
	}
}

func (lc *LoginCollector) Start(ctx context.Context) {
	ticker := time.NewTicker(lc.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lc.scan()
		}
	}
}

func (lc *LoginCollector) scan() {
	events, err := lc.getRecentLogins()
	if err != nil {
		return
	}

	lc.mu.Lock()
	lc.recentEvents = append(lc.recentEvents, events...)

	cutoff := time.Now().Add(-10 * time.Minute)
	var filtered []LoginEvent
	for _, e := range lc.recentEvents {
		if e.Timestamp.After(cutoff) {
			filtered = append(filtered, e)
		}
	}
	lc.recentEvents = filtered
	eventsCopy := make([]LoginEvent, len(lc.recentEvents))
	copy(eventsCopy, lc.recentEvents)
	lc.mu.Unlock()

	if alert := lc.detectBruteForce(eventsCopy); alert != nil {
		select {
		case lc.alertChan <- *alert:
		default:
		}
	}
}

func (lc *LoginCollector) getRecentLogins() ([]LoginEvent, error) {
	switch runtime.GOOS {
	case "windows":
		return lc.getWindowsLogins()
	case "linux":
		return lc.getLinuxLogins()
	case "darwin":
		return lc.getMacOSLogins()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func (lc *LoginCollector) getWindowsLogins() ([]LoginEvent, error) {
	script := `
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 100 | ForEach-Object {
    $props = @{Id=$_.Id; Time=$_.TimeCreated}
    if ($_.Id -eq 4624) {
        $props.Username = $_.Properties[5].Value
        $props.Ip = $_.Properties[18].Value
        $props.Success = $true
    } else {
        $props.Username = $_.Properties[5].Value
        $props.Ip = $_.Properties[19].Value
        $props.Success = $false
    }
    [PSCustomObject]$props
} | ConvertTo-Json -Compress
`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query Windows events: %w", err)
	}

	result := strings.TrimSpace(string(output))
	if result == "" || result == "[]" {
		return nil, nil
	}

	_ = result
	return nil, nil
}

func (lc *LoginCollector) getLinuxLogins() ([]LoginEvent, error) {
	var events []LoginEvent

	logFiles := []string{"/var/log/auth.log", "/var/log/secure"}
	for _, path := range logFiles {
		cmd := exec.Command("tail", "-n", "100", path)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.Contains(line, "Failed password") {
				event := LoginEvent{
					Timestamp: time.Now(),
					Success:   false,
					Type:      "ssh",
				}

				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "for" && i+1 < len(parts) {
						event.Username = strings.TrimRight(parts[i+1], "\n\r ")
					}
					if part == "from" && i+1 < len(parts) {
						event.SourceIP = strings.TrimRight(parts[i+1], "\n\r ")
					}
				}
				events = append(events, event)
			}

			if strings.Contains(line, "Accepted password") || strings.Contains(line, "Accepted publickey") {
				event := LoginEvent{
					Timestamp: time.Now(),
					Success:   true,
					Type:      "ssh",
				}
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "for" && i+1 < len(parts) {
						event.Username = strings.TrimRight(parts[i+1], "\n\r ")
					}
					if part == "from" && i+1 < len(parts) {
						event.SourceIP = strings.TrimRight(parts[i+1], "\n\r ")
					}
				}
				events = append(events, event)
			}

			if strings.Contains(line, "sudo:") && strings.Contains(line, "COMMAND=") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					event := LoginEvent{
						Username:  parts[0],
						Timestamp: time.Now(),
						Success:   true,
						Type:      "sudo",
					}
					events = append(events, event)
				}
			}
		}
	}

	return events, nil
}

func (lc *LoginCollector) getMacOSLogins() ([]LoginEvent, error) {
	cmd := exec.Command("log", "show", "--predicate", `subsystem == "com.apple.authd"`, "--last", "5m", "--style", "compact")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query macOS logs: %w", err)
	}

	var events []LoginEvent
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.Contains(line, "failed") {
			events = append(events, LoginEvent{
				Username:  extractUsername(line),
				SourceIP:  extractIP(line),
				Timestamp: time.Now(),
				Success:   false,
				Type:      "local",
			})
		}
	}

	return events, nil
}

func (lc *LoginCollector) detectBruteForce(events []LoginEvent) *BruteForceAlert {
	failCounts := make(map[string]int)
	windowStart := time.Now().Add(-lc.bruteWindow)

	for _, e := range events {
		if !e.Success && e.Timestamp.After(windowStart) && e.SourceIP != "" {
			failCounts[e.SourceIP]++
		}
	}

	for ip, count := range failCounts {
		if count >= lc.bruteThreshold {
			return &BruteForceAlert{
				SourceIP:  ip,
				Count:     count,
				Window:    lc.bruteWindow.String(),
				Timestamp: time.Now().UTC(),
			}
		}
	}

	return nil
}

func extractUsername(line string) string {
	parts := strings.Fields(line)
	for i, p := range parts {
		if p == "user" && i+1 < len(parts) {
			return strings.TrimRight(parts[i+1], "\n\r ")
		}
	}
	return "unknown"
}

func extractIP(line string) string {
	parts := strings.Fields(line)
	for _, p := range parts {
		if strings.Count(p, ".") == 3 {
			return p
		}
	}
	return ""
}

func (lc *LoginCollector) GetRecentLogins() ([]LoginEvent, error) {
	return lc.getRecentLogins()
}
