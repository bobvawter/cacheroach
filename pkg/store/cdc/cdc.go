// Copyright 2021 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cdc contains a utility for receiving notifications whenever
// the contents of a database table are changed.
package cdc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mandala/go-log"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
)

var (
	// Set is used by wire.
	Set = wire.NewSet(ProvideNotifier)
)

// Notifier is a factory for CDC notification channels.
type Notifier struct {
	db     *pgxpool.Pool
	logger *log.Logger
}

// ProvideNotifier is called by wire.
func ProvideNotifier(db *pgxpool.Pool, logger *log.Logger) *Notifier {
	return &Notifier{
		db:     db,
		logger: logger,
	}
}

// A Notification is emitted at least once for each data update.
type Notification struct {
	Table   string          // The table that was updated
	Key     json.RawMessage // The primary key for the table
	Payload json.RawMessage // The JSON payload associated with the notification
}

func (n *Notification) String() string {
	return fmt.Sprintf("%s %s %s", n.Table, string(n.Key), string(n.Payload))
}

// Notify creates a new CDC notification channel which will run until
// the context is canceled.
func (n *Notifier) Notify(ctx context.Context, tables []string) <-chan *Notification {
	// Set the feed cursor based on the caller's now.  This avoids any
	// "missed" updates since it may take a measurable amount of time in
	// order to actually start the feed.
	l := &loop{
		Notifier: n,
		ch:       make(chan *Notification, 16),
		resolved: fmt.Sprintf("%d.0", time.Now().UnixNano()),
		tables:   tables,
	}

	go func() {
		defer close(l.ch)
		for {
			err := l.run(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
				n.logger.Debugf("restarting notification loop after: %v", err)
			}
		}
	}()

	return l.ch
}

type loop struct {
	*Notifier
	ch       chan *Notification
	tables   []string
	resolved string
}

func (l *loop) run(ctx context.Context) error {
	const ts = 10 * time.Second
	const watch = 3 * ts

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	watchdog := time.NewTicker(watch)
	defer watchdog.Stop()
	go func() {
		select {
		case <-ctx.Done():
		case <-watchdog.C:
			l.logger.Warnf("cdc watchdog timer firing")
			cancel()
		}
	}()

	s := fmt.Sprintf(
		"EXPERIMENTAL CHANGEFEED FOR %s WITH resolved='%s', no_initial_scan",
		strings.Join(l.tables, ","), ts)
	if l.resolved != "" {
		s = fmt.Sprintf("%s, cursor='%s'", s, l.resolved)
	}
	l.logger.Tracef("creating changefeed using %q", s)

	rows, err := l.db.Query(ctx, s)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		// We'll see a NULL value for resolved-timestamp notifications.
		var maybeTable *string
		out := &Notification{}
		if err := rows.Scan(&maybeTable, &out.Key, &out.Payload); err != nil {
			return err
		}
		watchdog.Reset(watch)

		var envelope struct {
			After    json.RawMessage `json:"after"`
			Resolved string          `json:"resolved"`
		}
		if err := json.Unmarshal(out.Payload, &envelope); err != nil {
			return errors.Wrap(err, "decoding envelope")
		}
		if envelope.Resolved != "" {
			l.resolved = envelope.Resolved
			l.logger.Tracef("updated resolved timestamp: %s", envelope.Resolved)
			continue
		}
		if maybeTable != nil && len(envelope.After) > 0 {
			out.Table = *maybeTable
			out.Payload = envelope.After

			select {
			case <-ctx.Done():
				return ctx.Err()
			case l.ch <- out:
			}
		}
	}
	return rows.Err()
}
