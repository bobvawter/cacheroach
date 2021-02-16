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

// Package common contains utility code that is common between HTTP and
// RPC interfaces.
package common

import (
	"github.com/bobvawter/latch"
	"github.com/google/wire"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Set is used by wire.
var Set = wire.NewSet(
	ProvideBusyLatch,
	ProvideVHostMap,
)

// BusyLatch holds a latch.Counter when there is an active request.
type BusyLatch struct{ *latch.Counter }

// ProvideBusyLatch is called by wire.
func ProvideBusyLatch(auto promauto.Factory) BusyLatch {
	ret := latch.New()
	auto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "busy_latch_count",
		Help: "the number of currently-active requests",
	}, func() float64 { return float64(ret.Count()) })
	return BusyLatch{ret}
}
