package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/Raphasha27/kirov-endpoint-agent/internal/alerter"
	"github.com/Raphasha27/kirov-endpoint-agent/internal/collector"
	"github.com/Raphasha27/kirov-endpoint-agent/internal/config"
	"github.com/Raphasha27/kirov-endpoint-agent/internal/reporter"
)

var Version = "1.0.0"

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	setupLogger(cfg.LogLevel)
	log.Info().Str("version", Version).Str("agent_id", cfg.AgentID).Msg("kirov endpoint agent starting")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	alertMgr := alerter.New(1000)

	procAlertChan := make(chan collector.SuspiciousProcess, 100)
	loginAlertChan := make(chan collector.BruteForceAlert, 100)
	fileChangeChan := make(chan collector.FileChange, 100)
	healthChan := make(chan collector.SystemHealth, 100)

	rep := reporter.New(cfg.CoreURL, cfg.AgentID, log.Logger)
	if cfg.Token != "" {
		rep.SetToken(cfg.Token)
	}

	if cfg.Monitoring.ProcessMonitoring {
		procCollector := collector.NewProcessCollector(
			cfg.AllowedProcesses,
			cfg.BlacklistProcesses,
			procAlertChan,
		)
		go procCollector.Start(ctx)

		alertMgr.NewAlert(alerter.Alert{
			ID:        uuid.New(),
			AgentID:   cfg.AgentID,
			Type:      "agent_startup",
			Severity:  alerter.SeverityInfo,
			Title:     "Process monitoring started",
			Source:    "process_collector",
			Timestamp: time.Now().UTC(),
		})
	}

	if cfg.Monitoring.LoginMonitoring {
		loginCollector := collector.NewLoginCollector(loginAlertChan)
		go loginCollector.Start(ctx)

		alertMgr.NewAlert(alerter.Alert{
			ID:        uuid.New(),
			AgentID:   cfg.AgentID,
			Type:      "agent_startup",
			Severity:  alerter.SeverityInfo,
			Title:     "Login monitoring started",
			Source:    "login_collector",
			Timestamp: time.Now().UTC(),
		})
	}

	if cfg.Monitoring.FileIntegrity {
		fileChecker := collector.NewFileIntegrityChecker(cfg.WatchDirs, fileChangeChan)
		go fileChecker.Start(ctx)

		alertMgr.NewAlert(alerter.Alert{
			ID:        uuid.New(),
			AgentID:   cfg.AgentID,
			Type:      "agent_startup",
			Severity:  alerter.SeverityInfo,
			Title:     "File integrity monitoring started",
			Source:    "file_integrity",
			Timestamp: time.Now().UTC(),
		})
	}

	if cfg.Monitoring.SystemHealth {
		sysCollector := collector.NewSystemCollector()
		go sysCollector.Start(ctx, 60*time.Second, healthChan)
	}

	regInfo := reporter.AgentRegistration{
		AgentID:  cfg.AgentID,
		Hostname: getHostname(),
		OS:       runtime.GOOS + "/" + runtime.GOARCH,
		Version:  Version,
		Capabilities: []string{
			"process_monitoring",
			"login_monitoring",
			"file_integrity",
			"system_health",
		},
	}

	for i := 0; i < 3; i++ {
		if err := rep.Register(regInfo); err != nil {
			log.Warn().Err(err).Int("attempt", i+1).Msg("registration attempt failed")
			time.Sleep(time.Duration(i+1) * 5 * time.Second)
			continue
		}
		break
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "healthy",
			"agent_id": cfg.AgentID,
			"version":  Version,
			"uptime":   time.Now().Unix(),
		})
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(cfg)
		case http.MethodPost:
			var newCfg config.AgentConfig
			if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
				http.Error(w, "invalid config", http.StatusBadRequest)
				return
			}
			cfg.HeartbeatInterval = newCfg.HeartbeatInterval
			cfg.LogLevel = newCfg.LogLevel
			cfg.Monitoring = newCfg.Monitoring
			cfg.WatchDirs = newCfg.WatchDirs
			cfg.AllowedProcesses = newCfg.AllowedProcesses
			cfg.BlacklistProcesses = newCfg.BlacklistProcesses
			if err := cfg.Save(); err != nil {
				http.Error(w, "failed to save config", http.StatusInternalServerError)
				return
			}
			setupLogger(cfg.LogLevel)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	httpServer := &http.Server{
		Addr:         ":9090",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	go func() {
		log.Info().Str("addr", ":9090").Msg("agent HTTP server starting")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("HTTP server error")
		}
	}()

	go processAlerts(ctx, alertMgr, rep, procAlertChan, loginAlertChan, fileChangeChan, healthChan, cfg)
	go heartbeatLoop(ctx, rep, cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	cancel()

	pending := alertMgr.GetPending()
	if len(pending) > 0 {
		log.Info().Int("pending_alerts", len(pending)).Msg("flushing pending alerts before exit")
		for _, alert := range pending {
			rep.ReportAlert(reporter.AlertReport{
				AgentID:     alert.AgentID,
				ID:          alert.ID.String(),
				Type:        alert.Type,
				Severity:    string(alert.Severity),
				Title:       alert.Title,
				Description: alert.Description,
				Source:      alert.Source,
				Timestamp:   alert.Timestamp,
				Metadata:    alert.Metadata,
			})
		}
	}

	log.Info().Msg("agent stopped")
}

func setupLogger(level string) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func processAlerts(
	ctx context.Context,
	alertMgr *alerter.Alerter,
	rep *reporter.Reporter,
	procAlertChan <-chan collector.SuspiciousProcess,
	loginAlertChan <-chan collector.BruteForceAlert,
	fileChangeChan <-chan collector.FileChange,
	healthChan <-chan collector.SystemHealth,
	cfg *config.AgentConfig,
) {
	reportTicker := time.NewTicker(10 * time.Second)
	defer reportTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case sp := <-procAlertChan:
			alertMgr.NewAlert(alerter.Alert{
				ID:          uuid.New(),
				AgentID:     cfg.AgentID,
				Type:        "suspicious_process",
				Severity:    alerter.Severity(sp.Severity),
				Title:       fmt.Sprintf("Suspicious process detected: %s", sp.Name),
				Description: sp.Reason,
				Source:      "process_collector",
				Timestamp:   time.Now().UTC(),
				Metadata: map[string]string{
					"pid":  fmt.Sprintf("%d", sp.PID),
					"name": sp.Name,
				},
			})
		case bf := <-loginAlertChan:
			alertMgr.NewAlert(alerter.Alert{
				ID:          uuid.New(),
				AgentID:     cfg.AgentID,
				Type:        "brute_force",
				Severity:    alerter.SeverityHigh,
				Title:       "Brute force attack detected",
				Description: fmt.Sprintf("%d failed logins from %s in %s", bf.Count, bf.SourceIP, bf.Window),
				Source:      "login_collector",
				Timestamp:   bf.Timestamp,
				Metadata: map[string]string{
					"source_ip": bf.SourceIP,
					"count":     fmt.Sprintf("%d", bf.Count),
					"window":    bf.Window,
				},
			})
		case fc := <-fileChangeChan:
			alertMgr.NewAlert(alerter.Alert{
				ID:          uuid.New(),
				AgentID:     cfg.AgentID,
				Type:        "file_change",
				Severity:    alerter.SeverityMedium,
				Title:       fmt.Sprintf("File %s: %s", fc.ChangeType, fc.Path),
				Description: fmt.Sprintf("File %s was %s", fc.Path, fc.ChangeType),
				Source:      "file_integrity",
				Timestamp:   time.Now().UTC(),
				Metadata: map[string]string{
					"path":        fc.Path,
					"change_type": string(fc.ChangeType),
					"old_hash":    fc.OldHash,
					"new_hash":    fc.NewHash,
				},
			})
		case health := <-healthChan:
			rep.ReportHealth(reporter.HealthReport{
				AgentID:       cfg.AgentID,
				Timestamp:     time.Now().UTC(),
				CPUPercent:    health.CPUPercent,
				MemoryUsedGB:  health.MemoryUsedGB,
				MemoryTotalGB: health.MemoryTotalGB,
				DiskUsedGB:    health.DiskUsedGB,
				DiskTotalGB:   health.DiskTotalGB,
				Uptime:        uint64(time.Now().Unix()),
			})
		case <-reportTicker.C:
			pending := alertMgr.GetPending()
			for _, alert := range pending {
				err := rep.ReportAlert(reporter.AlertReport{
					AgentID:     alert.AgentID,
					ID:          alert.ID.String(),
					Type:        alert.Type,
					Severity:    string(alert.Severity),
					Title:       alert.Title,
					Description: alert.Description,
					Source:      alert.Source,
					Timestamp:   alert.Timestamp,
					Metadata:    alert.Metadata,
				})
				if err == nil {
					alertMgr.Acknowledge(alert.ID)
				}
			}
		}
	}
}

func heartbeatLoop(ctx context.Context, rep *reporter.Reporter, cfg *config.AgentConfig) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := rep.Heartbeat(); err != nil {
				log.Warn().Err(err).Msg("heartbeat failed")
			} else {
				log.Debug().Msg("heartbeat sent")
			}
		}
	}
}
