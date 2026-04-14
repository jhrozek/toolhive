// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package credential provides SPIFFE X.509-SVID credential loading and
// mTLS HTTP client construction for the agent proxy.
package credential

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// debounceDelay is the duration to wait after a filesystem event before
// reloading certificates. This accounts for cert-manager CSI driver
// writing cert and key files non-atomically.
const debounceDelay = 200 * time.Millisecond

// FileSource implements x509svid.Source by loading SVIDs from PEM files
// and watching for cert-manager CSI driver rotations.
type FileSource struct {
	certPath string
	keyPath  string
	current   atomic.Pointer[x509svid.SVID]
	watcher   *fsnotify.Watcher
	done      chan struct{}
	closeOnce sync.Once
	logger    *slog.Logger
}

// NewFileSource creates a FileSource that loads an X.509-SVID from the
// given PEM-encoded certificate and key files. It starts a background
// goroutine that watches the containing directory for filesystem events
// and automatically reloads the SVID when the files are rotated.
func NewFileSource(certPath, keyPath string) (*FileSource, error) {
	svid, err := x509svid.Load(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading initial SVID: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating filesystem watcher: %w", err)
	}

	fs := &FileSource{
		certPath: certPath,
		keyPath:  keyPath,
		watcher:  watcher,
		done:     make(chan struct{}),
		logger:   slog.Default().With("component", "file-source"),
	}
	fs.current.Store(svid)

	// Watch the directory rather than individual files so we catch
	// rotations where files are replaced via rename+create.
	certDir := filepath.Dir(certPath)
	keyDir := filepath.Dir(keyPath)

	if err := watcher.Add(certDir); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("watching certificate directory %q: %w", certDir, err)
	}
	if keyDir != certDir {
		if err := watcher.Add(keyDir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watching key directory %q: %w", keyDir, err)
		}
	}

	go fs.watchLoop()
	return fs, nil
}

// GetX509SVID returns the current X.509-SVID. This method is safe for
// concurrent use and satisfies the x509svid.Source interface.
func (fs *FileSource) GetX509SVID() (*x509svid.SVID, error) {
	svid := fs.current.Load()
	if svid == nil {
		return nil, fmt.Errorf("no SVID available")
	}
	return svid, nil
}

// Close stops the filesystem watcher goroutine and releases resources.
// It is safe to call Close multiple times.
func (fs *FileSource) Close() error {
	var err error
	fs.closeOnce.Do(func() {
		close(fs.done)
		err = fs.watcher.Close()
	})
	return err
}

func (fs *FileSource) watchLoop() {
	var debounce *time.Timer

	for {
		select {
		case <-fs.done:
			if debounce != nil {
				debounce.Stop()
			}
			return

		case event, ok := <-fs.watcher.Events:
			if !ok {
				return
			}
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}

			// Debounce: cert and key may be written separately.
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(debounceDelay, func() {
				fs.reload()
			})

		case err, ok := <-fs.watcher.Errors:
			if !ok {
				return
			}
			fs.logger.Error("filesystem watcher error", "error", err)
		}
	}
}

func (fs *FileSource) reload() {
	svid, err := x509svid.Load(fs.certPath, fs.keyPath)
	if err != nil {
		fs.logger.Error("failed to reload SVID", "error", err)
		return
	}
	fs.current.Store(svid)
	fs.logger.Info("reloaded SVID", "spiffe_id", svid.ID.String())
}
