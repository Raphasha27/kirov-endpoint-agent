package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ChangeType string

const (
	ChangeAdded    ChangeType = "added"
	ChangeModified ChangeType = "modified"
	ChangeDeleted  ChangeType = "deleted"
)

type FileState struct {
	Path        string    `json:"path"`
	HashSHA256  string    `json:"hash_sha256"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time"`
	Permissions os.FileMode `json:"permissions"`
}

type FileChange struct {
	Path       string     `json:"path"`
	ChangeType ChangeType `json:"change_type"`
	OldHash    string     `json:"old_hash"`
	NewHash    string     `json:"new_hash"`
}

type FileIntegrityChecker struct {
	mu           sync.Mutex
	baseline     map[string]FileState
	watchDirs    []string
	alertChan    chan<- FileChange
	scanInterval time.Duration
}

func NewFileIntegrityChecker(watchDirs []string, alertChan chan<- FileChange) *FileIntegrityChecker {
	return &FileIntegrityChecker{
		baseline:     make(map[string]FileState),
		watchDirs:    watchDirs,
		alertChan:    alertChan,
		scanInterval: 5 * time.Minute,
	}
}

func (fc *FileIntegrityChecker) Start(ctx context.Context) {
	baseline, err := fc.snapshot()
	if err == nil {
		fc.mu.Lock()
		fc.baseline = baseline
		fc.mu.Unlock()
	}

	ticker := time.NewTicker(fc.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fc.check()
		}
	}
}

func (fc *FileIntegrityChecker) check() {
	current, err := fc.snapshot()
	if err != nil {
		return
	}

	fc.mu.Lock()
	baseline := make(map[string]FileState, len(fc.baseline))
	for k, v := range fc.baseline {
		baseline[k] = v
	}
	fc.mu.Unlock()

	changes := fc.compare(baseline, current)

	fc.mu.Lock()
	fc.baseline = current
	fc.mu.Unlock()

	for _, change := range changes {
		select {
		case fc.alertChan <- change:
		default:
		}
	}
}

func (fc *FileIntegrityChecker) snapshot() (map[string]FileState, error) {
	states := make(map[string]FileState)

	for _, dir := range fc.watchDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}

			hash, err := fc.hashFile(path)
			if err != nil {
				return nil
			}

			states[path] = FileState{
				Path:        path,
				HashSHA256:  hash,
				Size:        info.Size(),
				ModTime:     info.ModTime(),
				Permissions: info.Mode().Perm(),
			}
			return nil
		})
		if err != nil {
			continue
		}
	}

	return states, nil
}

func (fc *FileIntegrityChecker) compare(baseline, current map[string]FileState) []FileChange {
	var changes []FileChange

	for path, curState := range current {
		baseState, exists := baseline[path]
		if !exists {
			changes = append(changes, FileChange{
				Path:       path,
				ChangeType: ChangeAdded,
				NewHash:    curState.HashSHA256,
			})
		} else if baseState.HashSHA256 != curState.HashSHA256 {
			changes = append(changes, FileChange{
				Path:       path,
				ChangeType: ChangeModified,
				OldHash:    baseState.HashSHA256,
				NewHash:    curState.HashSHA256,
			})
		}
	}

	for path, baseState := range baseline {
		if _, exists := current[path]; !exists {
			changes = append(changes, FileChange{
				Path:       path,
				ChangeType: ChangeDeleted,
				OldHash:    baseState.HashSHA256,
			})
		}
	}

	return changes
}

func (fc *FileIntegrityChecker) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to hash %s: %w", path, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
