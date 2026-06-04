package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type MonitoringConfig struct {
	ProcessMonitoring bool `yaml:"process_monitoring"`
	LoginMonitoring   bool `yaml:"login_monitoring"`
	FileIntegrity     bool `yaml:"file_integrity"`
	SystemHealth      bool `yaml:"system_health"`
}

type AgentConfig struct {
	AgentID            string           `yaml:"agent_id"`
	CoreURL            string           `yaml:"core_url"`
	Token              string           `yaml:"-"`
	HeartbeatInterval  time.Duration    `yaml:"-"`
	HeartbeatSec       int              `yaml:"heartbeat_interval"`
	LogLevel           string           `yaml:"log_level"`
	Monitoring         MonitoringConfig `yaml:"monitoring"`
	WatchDirs          []string         `yaml:"watch_dirs"`
	AllowedProcesses   []string         `yaml:"allowed_processes"`
	BlacklistProcesses []string         `yaml:"blacklist_processes"`
	ConfigPath         string           `yaml:"-"`
}

func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		AgentID:           uuid.New().String(),
		CoreURL:           "http://localhost:8000",
		HeartbeatInterval: 60 * time.Second,
		HeartbeatSec:      60,
		LogLevel:          "info",
		Monitoring: MonitoringConfig{
			ProcessMonitoring: true,
			LoginMonitoring:   true,
			FileIntegrity:     true,
			SystemHealth:      true,
		},
		WatchDirs:          []string{"/etc", "/usr/local/bin", "/opt"},
		AllowedProcesses:   []string{"systemd", "sshd", "nginx", "postgres", "redis-server", "dockerd", "python3", "node", "go"},
		BlacklistProcesses: []string{"mimikatz", "powershell -enc", "nc", "ncat", "cryptominer"},
	}
}

func Load(path string) (*AgentConfig, error) {
	cfg := DefaultConfig()
	cfg.ConfigPath = path

	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
		if cfg.HeartbeatSec > 0 {
			cfg.HeartbeatInterval = time.Duration(cfg.HeartbeatSec) * time.Second
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if v := os.Getenv("KIROV_CORE_URL"); v != "" {
		cfg.CoreURL = v
	}
	if v := os.Getenv("KIROV_AGENT_ID"); v != "" {
		cfg.AgentID = v
	}
	if v := os.Getenv("KIROV_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("KIROV_HEARTBEAT_INTERVAL"); v != "" {
		sec, err := strconv.Atoi(v)
		if err == nil && sec > 0 {
			cfg.HeartbeatInterval = time.Duration(sec) * time.Second
			cfg.HeartbeatSec = sec
		}
	}
	if v := os.Getenv("KIROV_WATCH_DIRS"); v != "" {
		cfg.WatchDirs = strings.Split(v, ",")
	}
	if v := os.Getenv("KIROV_ALLOWED_PROCESSES"); v != "" {
		cfg.AllowedProcesses = strings.Split(v, ",")
	}
	if v := os.Getenv("KIROV_BLACKLIST_PROCESSES"); v != "" {
		cfg.BlacklistProcesses = strings.Split(v, ",")
	}
	if v := os.Getenv("KIROV_AGENT_TOKEN"); v != "" {
		cfg.Token = v
	}

	return cfg, nil
}

func (c *AgentConfig) Save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(c.ConfigPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}
