package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type Reporter struct {
	coreURL       string
	agentID       string
	token         string
	client        *http.Client
	log           zerolog.Logger
	mu            sync.Mutex
	pendingAlerts []json.RawMessage
	maxBuffer     int
	maxRetries    int
}

type AgentRegistration struct {
	AgentID   string `json:"agent_id"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Version   string `json:"version"`
	Capabilities []string `json:"capabilities"`
}

type HealthReport struct {
	AgentID       string    `json:"agent_id"`
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryUsedGB  float64   `json:"memory_used_gb"`
	MemoryTotalGB float64   `json:"memory_total_gb"`
	DiskUsedGB    float64   `json:"disk_used_gb"`
	DiskTotalGB   float64   `json:"disk_total_gb"`
	Uptime        uint64    `json:"uptime_seconds"`
}

type AlertReport struct {
	AgentID     string            `json:"agent_id"`
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type HeartbeatPayload struct {
	AgentID    string    `json:"agent_id"`
	Timestamp  time.Time `json:"timestamp"`
	Status     string    `json:"status"`
}

func New(coreURL, agentID string, log zerolog.Logger) *Reporter {
	return &Reporter{
		coreURL:    coreURL,
		agentID:    agentID,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
			},
		},
		log:        log,
		maxBuffer:  1000,
		maxRetries: 3,
	}
}

func (r *Reporter) SetToken(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.token = token
}

func (r *Reporter) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	url := r.coreURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kirov-endpoint-agent/1.0")

	r.mu.Lock()
	token := r.token
	r.mu.Unlock()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return r.client.Do(req)
}

func (r *Reporter) retryRequest(method, path string, body []byte) (*http.Response, error) {
	var lastErr error
	var resp *http.Response

	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			r.log.Debug().Int("attempt", attempt).Dur("backoff", backoff).Msg("retrying request")
			time.Sleep(backoff)
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}

		resp, lastErr = r.doRequest(method, path, reader)
		if lastErr != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return resp, nil
		}
		lastErr = fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", r.maxRetries, lastErr)
}

func (r *Reporter) Register(reg AgentRegistration) error {
	body, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	resp, err := r.retryRequest("POST", "/api/v1/agents/register", body)
	if err != nil {
		r.bufferAlert(reg)
		return fmt.Errorf("registration failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var result struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Token != "" {
			r.SetToken(result.Token)
		}
		r.log.Info().Msg("agent registered successfully")
		return nil
	}

	return fmt.Errorf("registration returned status %d", resp.StatusCode)
}

func (r *Reporter) ReportHealth(health HealthReport) error {
	body, err := json.Marshal(health)
	if err != nil {
		return fmt.Errorf("failed to marshal health: %w", err)
	}

	path := fmt.Sprintf("/api/v1/agents/%s/health", r.agentID)
	resp, err := r.retryRequest("POST", path, body)
	if err != nil {
		r.bufferAlert(health)
		return fmt.Errorf("health report failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (r *Reporter) ReportAlert(alert AlertReport) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	path := fmt.Sprintf("/api/v1/agents/%s/alerts", r.agentID)
	resp, err := r.retryRequest("POST", path, body)
	if err != nil {
		r.bufferAlert(alert)
		return fmt.Errorf("alert report failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (r *Reporter) Heartbeat() error {
	payload := HeartbeatPayload{
		AgentID:   r.agentID,
		Timestamp: time.Now().UTC(),
		Status:    "healthy",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	path := fmt.Sprintf("/api/v1/agents/%s/heartbeat", r.agentID)
	resp, err := r.retryRequest("POST", path, body)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (r *Reporter) SendBatch(events []interface{}) error {
	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal batch: %w", err)
	}

	path := fmt.Sprintf("/api/v1/agents/%s/batch", r.agentID)
	resp, err := r.retryRequest("POST", path, body)
	if err != nil {
		return fmt.Errorf("batch send failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (r *Reporter) FlushPending(ctx context.Context) []json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]json.RawMessage, len(r.pendingAlerts))
	copy(result, r.pendingAlerts)
	r.pendingAlerts = r.pendingAlerts[:0]
	return result
}

func (r *Reporter) bufferAlert(data interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.pendingAlerts) >= r.maxBuffer {
		r.log.Warn().Int("buffer_size", r.maxBuffer).Msg("alert buffer full, dropping oldest alert")
		r.pendingAlerts = r.pendingAlerts[1:]
	}

	raw, err := json.Marshal(data)
	if err != nil {
		r.log.Error().Err(err).Msg("failed to marshal alert for buffer")
		return
	}

	r.pendingAlerts = append(r.pendingAlerts, raw)
	r.log.Debug().Int("buffer_size", len(r.pendingAlerts)).Msg("alert buffered")
}
