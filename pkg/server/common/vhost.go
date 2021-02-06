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

package common

import (
	"context"
	"strings"
	"sync"
	"time"

	"regexp"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/vhost"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// VHostMap resolves hostnames against the
// virtual-host configuration in order to return the relevant VHost
// entry into calling contexts.
type VHostMap struct {
	logger *log.Logger
	mu     struct {
		sync.RWMutex
		hosts map[string]*vhost.VHost
	}
	vhosts vhost.VHostsServer
}

// ProvideVHostMap is called by wire.
func ProvideVHostMap(
	ctx context.Context,
	logger *log.Logger,
	vhosts vhost.VHostsServer,
) (*VHostMap, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	ret := &VHostMap{
		logger: logger,
		vhosts: vhosts,
	}
	var err error
	ret.mu.hosts, err = ret.loadHostMap(ctx)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	go ret.refreshLoop(ctx)

	return ret, cancel, nil
}

var extractPort = regexp.MustCompile(`:\d+$`)

// Resolve maps the hostname to a VHost, or returns nil if no mapping is
// available.
func (m *VHostMap) Resolve(hostname string) *vhost.VHost {
	m.mu.RLock()
	defer m.mu.RUnlock()

	idxs := extractPort.FindStringIndex(hostname)
	if len(idxs) == 2 {
		hostname = hostname[:idxs[0]]
	}

	ret := m.mu.hosts[strings.ToLower(hostname)]
	if ret == nil {
		ret = m.mu.hosts["*"]
	}
	return ret
}

func (m *VHostMap) loadHostMap(ctx context.Context) (map[string]*vhost.VHost, error) {
	vhostCollector := &vhostCollector{ctx: ctx}
	if err := m.vhosts.List(&emptypb.Empty{}, vhostCollector); err != nil {
		return nil, err
	}

	ret := make(map[string]*vhost.VHost)
	for _, h := range vhostCollector.hosts {
		h.Vhost = strings.ToLower(h.Vhost)
		ret[h.Vhost] = h
	}
	return ret, nil
}

func (m *VHostMap) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if next, err := m.loadHostMap(ctx); err != nil {
				m.logger.Warnf("could not refresh vhost map: %v", err)
			} else {
				m.mu.Lock()
				m.mu.hosts = next
				m.mu.Unlock()
			}
		}
	}
}

type vhostCollector struct {
	grpc.ServerStream
	ctx   context.Context
	hosts []*vhost.VHost
}

func (x *vhostCollector) Context() context.Context {
	return x.ctx
}

func (x *vhostCollector) Send(msg *vhost.VHost) error {
	x.hosts = append(x.hosts, msg)
	return nil
}
