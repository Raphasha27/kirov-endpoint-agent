package alerter

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

var validSeverities = map[Severity]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
	SeverityInfo:     true,
}

type Alert struct {
	ID          uuid.UUID              `json:"id"`
	AgentID     string                 `json:"agent_id"`
	Type        string                 `json:"type"`
	Severity    Severity               `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
	Acknowledged bool                  `json:"-"`
}

type Alerter struct {
	mu       sync.RWMutex
	alerts   []Alert
	pending  []Alert
	maxQueue int
}

func New(maxQueue int) *Alerter {
	if maxQueue <= 0 {
		maxQueue = 1000
	}
	return &Alerter{
		alerts:   make([]Alert, 0, maxQueue),
		pending:  make([]Alert, 0, maxQueue),
		maxQueue: maxQueue,
	}
}

func (a *Alerter) NewAlert(alert Alert) error {
	if alert.ID == uuid.Nil {
		alert.ID = uuid.New()
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now().UTC()
	}
	if !validSeverities[alert.Severity] {
		return fmt.Errorf("invalid severity: %s", alert.Severity)
	}
	if alert.Title == "" {
		return fmt.Errorf("alert title is required")
	}
	if alert.AgentID == "" {
		return fmt.Errorf("alert agent_id is required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, existing := range a.alerts {
		if existing.ID == alert.ID {
			return nil
		}
	}

	if len(a.alerts) >= a.maxQueue {
		return fmt.Errorf("alert queue full (%d)", a.maxQueue)
	}

	a.alerts = append(a.alerts, alert)
	a.pending = append(a.pending, alert)
	return nil
}

func (a *Alerter) GetPending() []Alert {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]Alert, len(a.pending))
	copy(result, a.pending)
	return result
}

func (a *Alerter) Acknowledge(id uuid.UUID) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i := range a.alerts {
		if a.alerts[i].ID == id {
			a.alerts[i].Acknowledged = true
			break
		}
	}

	for i := range a.pending {
		if a.pending[i].ID == id {
			a.pending = append(a.pending[:i], a.pending[i+1:]...)
			return
		}
	}
}

func (a *Alerter) ClearAcknowledged() {
	a.mu.Lock()
	defer a.mu.Unlock()

	filtered := make([]Alert, 0, len(a.alerts))
	for _, alert := range a.alerts {
		if !alert.Acknowledged {
			filtered = append(filtered, alert)
		}
	}
	a.alerts = filtered
}

func (a *Alerter) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.alerts)
}

func (a *Alerter) PendingLen() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.pending)
}
