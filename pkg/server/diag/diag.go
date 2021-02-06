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

// Package diag contains code to retrieve diagnostic information from
// the server.
package diag

import (
	"context"
	"os"
	"strings"

	"net/http"

	"github.com/bobvawter/cacheroach/api/diag"
	"github.com/google/wire"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type contextKey int

var (
	// RequestKey is a context key that should return an *http.Request.
	RequestKey contextKey = 0
)

// Set is used by wire.
var Set = wire.NewSet(
	wire.Struct(new(Diags)),
	wire.Bind(new(diag.DiagsServer), new(*Diags)),
)

// Diags implements diag.DiagsServer.
type Diags struct {
	diag.UnsafeDiagsServer
}

var _ diag.DiagsServer = (*Diags)(nil)

// Echo implements diag.DiagsServer.
func (d *Diags) Echo(ctx context.Context, _ *emptypb.Empty) (*diag.DiagResponse, error) {
	resp := &diag.DiagResponse{
		Environment: make(map[string]*diag.DiagResponse_Meta),
		HttpHeaders: make(map[string]*diag.DiagResponse_Meta),
		RpcMeta:     make(map[string]*diag.DiagResponse_Meta),
	}
	if h, err := os.Hostname(); err != nil {
		resp.Hostname = h
	}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for key, elts := range md {
			resp.RpcMeta[key] = &diag.DiagResponse_Meta{Value: elts}
		}
	}

	if req, ok := ctx.Value(RequestKey).(*http.Request); ok {
		for key, elts := range req.Header {
			resp.HttpHeaders[key] = &diag.DiagResponse_Meta{Value: elts}
		}
	}

	for _, e := range os.Environ() {
		parts := strings.Split(e, "=")
		resp.Environment[parts[0]] = &diag.DiagResponse_Meta{Value: []string{parts[1]}}
	}

	return resp, nil
}
