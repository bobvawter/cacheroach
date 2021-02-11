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

package upload

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"net/http"
	"net/url"

	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/upload"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/fs"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/wire"
	lru "github.com/hashicorp/golang-lru"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxChunkSize = 2 * 1024 * 1024

// Set is used by wire.
var Set = wire.NewSet(
	ProvideServer,
	wire.Bind(new(upload.UploadsServer), new(*Server)),
)

// Server implements the upload.UploadsServer API.
type Server struct {
	blobs  *blob.Store
	cfg    *config.Config
	db     *pgxpool.Pool
	fs     *fs.Store
	logger *log.Logger
	upload.UnsafeUploadsServer

	// map[uuid.UUID]*BeginRequest; we'll try to cut down on the work
	// needed to commit a file under the assumption that a client will
	// probably stay connected to the same backend for the duration of a
	// transfer.
	cache *lru.TwoQueueCache
}

// ProvideServer is used by wire.
func ProvideServer(
	blobs *blob.Store,
	cfg *config.Config,
	db *pgxpool.Pool,
	fs *fs.Store,
	logger *log.Logger,
) (*Server, error) {
	if len(cfg.SigningKeys) == 0 {
		return nil, errors.New("HMAC signing keys must be specified")
	}
	cache, err := lru.New2Q(1024)
	if err != nil {
		return nil, err
	}
	return &Server{
		blobs:  blobs,
		cache:  cache,
		cfg:    cfg,
		db:     db,
		fs:     fs,
		logger: logger,
	}, nil
}

var _ upload.UploadsServer = (*Server)(nil)

// Begin implements upload.UploadsServer.
func (s *Server) Begin(ctx context.Context, req *upload.BeginRequest) (*upload.BeginResponse, error) {
	sn := session.FromContext(ctx)
	id := upload.NewID()
	now := time.Now()
	s.cache.Add(id.AsUUID(), req)

	if err := util.Retry(ctx, func(ctx context.Context) error {
		_, err := s.db.Exec(ctx,
			"INSERT INTO uploads (upload, tenant, path, principal, session, started_at) "+
				"VALUES ($1, $2, $3, $4, $5, $6)",
			id, req.Tenant, req.Path, sn.PrincipalId, sn.ID, now,
		)
		return err
	}); err != nil {
		return nil, err
	}

	resp := &upload.BeginResponse{
		MaxChunkSize: maxChunkSize,
		State: &upload.TransferState{
			Deadline: timestamppb.New(now.Add(s.cfg.UploadTimeout).Round(time.Second)),
			ID:       id,
			TenantId: req.Tenant,
		},
	}

	if req.GetEmpty() {
		req.Committed = &upload.BeginRequest_Contents{Contents: nil}
	}

	if t, ok := req.Committed.(*upload.BeginRequest_Contents); ok {
		h := sha256.New()
		if len(t.Contents) > 0 {
			_, err := s.blobs.InsertToRope(ctx, req.Tenant, id.AsUUID(),
				bytes.NewReader(t.Contents), h, 0)
			if err != nil {
				return nil, err
			}
		}
		var x blob.Hash
		h.Sum(x[:0])
		meta := &fs.FileMeta{
			Path:    req.Path,
			Version: -1, // TODO(bob): Add versioning to upload messages.
		}

		if err := s.blobs.CommitRope(ctx, req.Tenant, id.AsUUID(), x); err != nil {
			return nil, err
		}

		if err := s.fs.FileSystem(req.Tenant).Put(ctx, meta, x); err != nil {
			return nil, err
		}

		return &upload.BeginResponse{Committed: true}, nil
	}

	return resp, s.sign(resp.State)
}

// Commit implements upload.UploadsServer.
func (s *Server) Commit(ctx context.Context, req *upload.CommitRequest) (*upload.CommitResponse, error) {
	state := req.State
	if ok, err := s.validate(state); err != nil {
		return nil, err
	} else if !ok {
		return nil, status.Error(codes.InvalidArgument, "bad state signature")
	}

	h := sha256.New()
	if len(state.Data) > 0 {
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state.Data); err != nil {
			return nil, err
		}
	}

	var x blob.Hash
	h.Sum(x[:0])

	if err := s.blobs.CommitRope(ctx, state.TenantId, state.ID.AsUUID(), x); err != nil {
		return nil, err
	}

	var tID *tenant.ID
	var filePath string

	if found, ok := s.cache.Get(state.ID.AsUUID()); ok {
		req := found.(*upload.BeginRequest)
		tID = req.Tenant
		filePath = req.Path
	} else {
		tID = &tenant.ID{}
		row := s.db.QueryRow(ctx, "SELECT tenant, path FROM uploads WHERE upload = $1", state.ID)
		if err := row.Scan(tID, &filePath); err == pgx.ErrNoRows {
			return nil, status.Error(codes.InvalidArgument, "upload not found")
		} else if err != nil {
			return nil, err
		}
	}

	meta := &fs.FileMeta{
		Meta:    req.Meta,
		Path:    filePath,
		Version: -1, // TODO(bob): Add versioning to upload messages.
	}

	if err := s.fs.FileSystem(tID).Put(ctx, meta, x); err != nil {
		return nil, err
	}

	return &upload.CommitResponse{}, nil
}

// Fetch implements upload.UploadsServer.
func (s *Server) Fetch(ctx context.Context, req *upload.FetchRequest) (*upload.FetchResponse, error) {
	var err error
	sn := session.FromContext(ctx)

	r := &http.Request{}
	r.URL, err = url.Parse(req.RemoteUrl)
	if err != nil {
		return nil, err
	}

	if req.RemoteMethod == "" {
		r.Method = http.MethodGet
	} else {
		r.Method = req.RemoteMethod
	}

	r.Header = make(http.Header)
	for k, v := range req.RemoteHeaders {
		r.Header.Add(k, v)
	}
	r.Header.Add("x-cacheroach-session", sn.ID.AsUUID().String())

	files := s.fs.FileSystem(req.Tenant)
	if f, err := files.Open(req.Path); err == nil {
		if stat, err := f.Stat(); err == nil {
			r.Header.Add("if-modified-since", stat.ModTime().Format(http.TimeFormat))
		}
	}

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return &upload.FetchResponse{
			RemoteHttpCode:    int32(resp.StatusCode),
			RemoteHttpMessage: resp.Status,
		}, nil
	}

	h, err := s.blobs.EnsureBlob(ctx, req.Tenant, resp.Body)
	if err != nil {
		return nil, err
	}

	err = files.Put(ctx, &fs.FileMeta{
		Path:    req.Path,
		Version: -1, // Overwrite.
	}, h)
	if err != nil {
		return nil, err
	}

	return &upload.FetchResponse{RemoteHttpCode: 200}, nil
}

// Transfer implements upload.UploadsServer.
func (s *Server) Transfer(ctx context.Context, req *upload.TransferRequest) (*upload.TransferResponse, error) {
	if l := len(req.Data); l == 0 {
		return nil, status.Error(codes.InvalidArgument, "no data in request")
	} else if l > maxChunkSize {
		return nil, status.Error(codes.InvalidArgument, "reduce chunk size")
	}

	state := req.State
	if ok, err := s.validate(state); err != nil {
		return nil, err
	} else if !ok {
		return nil, status.Error(codes.InvalidArgument, "bad state signature")
	}

	// Possibly resume our ongoing content hash.
	h := sha256.New()
	if len(state.Data) > 0 {
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state.Data); err != nil {
			return nil, err
		}
	}

	// Add the data to the rope.
	var err error
	state.Offset, err = s.blobs.InsertToRope(ctx, state.TenantId, state.ID.AsUUID(),
		bytes.NewReader(req.Data), h, state.Offset)
	if err != nil {
		return nil, err
	}

	// Read out the current state of the hash.
	state.Data, err = h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Sign the status data.
	if err := s.sign(state); err != nil {
		return nil, err
	}

	return &upload.TransferResponse{State: state}, nil
}

func (s *Server) sign(state *upload.TransferState) error {
	next, err := stateMAC(state, s.cfg.SigningKeys[0])
	if err == nil {
		state.Signature = next
	}
	return err
}

func (s *Server) validate(state *upload.TransferState) (bool, error) {
	if time.Now().After(state.GetDeadline().AsTime()) {
		return false, nil
	}
	for i := range s.cfg.SigningKeys {
		test, err := stateMAC(state, s.cfg.SigningKeys[i])
		if err != nil {
			return false, err
		}
		if hmac.Equal(state.Signature, test) {
			return true, nil
		}
	}
	return false, nil
}

// stateMAC computes the value used to sign a TransferState.
func stateMAC(state *upload.TransferState, key []byte) ([]byte, error) {
	// proto.Marshal has no guaranteed stability, so we'll cherry-pick
	// the relevant data. Do note that this can't be extended unless a
	// version field is also added to TransferState.
	var data []byte
	data = protowire.AppendBytes(data, state.ID.Data)
	data = protowire.AppendVarint(data, uint64(state.Offset))
	data = protowire.AppendBytes(data, state.Data)
	data = protowire.AppendVarint(data, uint64(state.Deadline.Seconds))
	data = protowire.AppendBytes(data, state.TenantId.Data)

	h := hmac.New(sha512.New, key)
	if _, err := h.Write(data); err != nil {
		return nil, err
	}

	return h.Sum(make([]byte, 0, sha512.BlockSize)), nil
}
