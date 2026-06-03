package collector

import (
	"context"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type SystemInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Platform      string `json:"platform"`
	KernelVersion string `json:"kernel_version"`
	Uptime        uint64 `json:"uptime_seconds"`
	Arch          string `json:"arch"`
	NumCPU        int    `json:"num_cpu"`
}

type SystemHealth struct {
	CPUPercent        float64 `json:"cpu_percent"`
	MemoryUsedGB      float64 `json:"memory_used_gb"`
	MemoryTotalGB     float64 `json:"memory_total_gb"`
	MemoryUsedPercent float64 `json:"memory_used_percent"`
	DiskUsedGB        float64 `json:"disk_used_gb"`
	DiskTotalGB       float64 `json:"disk_total_gb"`
	DiskUsedPercent   float64 `json:"disk_used_percent"`
	NetworkBytesSent  uint64  `json:"network_bytes_sent"`
	NetworkBytesRecv  uint64  `json:"network_bytes_recv"`
	LoadAverage1      float64 `json:"load_average_1"`
	LoadAverage5      float64 `json:"load_average_5"`
	LoadAverage15     float64 `json:"load_average_15"`
}

type SystemCollector struct {
	info          SystemInfo
	prevNetSent   uint64
	prevNetRecv   uint64
}

func NewSystemCollector() *SystemCollector {
	sc := &SystemCollector{}
	sc.collectInfo()
	return sc
}

func (sc *SystemCollector) Start(ctx context.Context, interval time.Duration, healthChan chan<- SystemHealth) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	health, err := sc.GetSystemHealth()
	if err == nil {
		select {
		case healthChan <- health:
		default:
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			health, err := sc.GetSystemHealth()
			if err != nil {
				continue
			}
			select {
			case healthChan <- health:
			default:
			}
		}
	}
}

func (sc *SystemCollector) collectInfo() {
	hostInfo, err := host.Info()
	if err != nil {
		return
	}

	sc.info = SystemInfo{
		Hostname:      hostInfo.Hostname,
		OS:            runtime.GOOS,
		Platform:      hostInfo.Platform + " " + hostInfo.PlatformVersion,
		KernelVersion: hostInfo.KernelVersion,
		Uptime:        hostInfo.Uptime,
		Arch:          runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
	}
}

func (sc *SystemCollector) GetSystemInfo() SystemInfo {
	return sc.info
}

func (sc *SystemCollector) GetSystemHealth() (SystemHealth, error) {
	var health SystemHealth

	cpuPercents, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercents) > 0 {
		health.CPUPercent = cpuPercents[0]
	}

	memInfo, err := mem.VirtualMemory()
	if err == nil {
		health.MemoryUsedGB = float64(memInfo.Used) / (1024 * 1024 * 1024)
		health.MemoryTotalGB = float64(memInfo.Total) / (1024 * 1024 * 1024)
		health.MemoryUsedPercent = memInfo.UsedPercent
	}

	diskInfo, err := disk.Usage("/")
	if err == nil {
		health.DiskUsedGB = float64(diskInfo.Used) / (1024 * 1024 * 1024)
		health.DiskTotalGB = float64(diskInfo.Total) / (1024 * 1024 * 1024)
		health.DiskUsedPercent = diskInfo.UsedPercent
	}

	netIO, err := net.IOCounters(false)
	if err == nil && len(netIO) > 0 {
		if sc.prevNetSent > 0 && sc.prevNetRecv > 0 {
			health.NetworkBytesSent = netIO[0].BytesSent - sc.prevNetSent
			health.NetworkBytesRecv = netIO[0].BytesRecv - sc.prevNetRecv
		}
		sc.prevNetSent = netIO[0].BytesSent
		sc.prevNetRecv = netIO[0].BytesRecv
	}

	loadAvg, err := load.Avg()
	if err == nil {
		health.LoadAverage1 = loadAvg.Load1
		health.LoadAverage5 = loadAvg.Load5
		health.LoadAverage15 = loadAvg.Load15
	}

	return health, nil
}
