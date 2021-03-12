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

package fs

import (
	"context"
	"net/url"
	"path"
	"time"

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/file"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/claims"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/jackc/pgx/v4/pgxpool"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server implements the file.FilesServer interface.
type Server struct {
	Config *config.Config
	DB     *pgxpool.Pool
	FS     *Store

	// Override for testing.
	limitOverride int `wire:"-"`

	file.UnsafeFilesServer `wire:"-"`
}

var _ file.FilesServer = (*Server)(nil)

// Delete implements file.FilesServer.
func (s *Server) Delete(ctx context.Context, req *file.DeleteRequest) (*emptypb.Empty, error) {
	err := s.FS.FileSystem(req.Tenant).Delete(ctx, req.Path)
	return &emptypb.Empty{}, err
}

// List implements file.FilesServer.
func (s *Server) List(ctx context.Context, req *file.ListRequest) (*file.ListResponse, error) {
	listLimit := 1024
	if s.limitOverride > 0 {
		listLimit = s.limitOverride
	}

	p := path.Clean(req.Path)
	switch p {
	case ".", "/":
		p = ""
	}

	var when time.Time
	if asOf := req.GetCursor().GetAsOf(); asOf != nil {
		when = asOf.AsTime()
	} else {
		when = time.Now()
	}

	// This query uses a CTE to select the most recent version of any
	// paths that match the paginated query. The versioned paths are
	// then used to select the file metadata. We do need to issue a
	// sub-query against the ropes table to find the offset and length
	// of the last chunk of the file in order to compute the file's
	// total length. The use of join hints is belt-and-suspenders.
	const q = `
WITH
latest_version AS (
  SELECT tenant, path, max(version) AS version
  FROM files
  WHERE mtime <= $5
  GROUP BY tenant, path
  ORDER BY tenant, path),
data AS (
  SELECT tenant, path, version, ctime, hash, meta, mtime
  FROM files
  INNER MERGE JOIN latest_version USING(tenant,path,version)
  WHERE tenant = $1
  AND (path = $2 OR path LIKE $3)
  AND (path > $4)
  AND dtime IS NULL
  LIMIT $6),
rope_data AS (
  SELECT tenant, hash, off, chunk_length
  FROM ropes
  JOIN data USING (tenant, hash)
  WHERE tenant = $1 AND hash IS NOT NULL),
rope_ends AS (
  SELECT tenant, hash, max(off) as off
  FROM rope_data
  GROUP BY tenant, hash),
rope_length AS (
  SELECT DISTINCT tenant, hash, off + chunk_length as size
  FROM rope_ends
  INNER MERGE JOIN rope_data USING (tenant, hash, off))
SELECT path, version, ctime, meta, mtime, IFNULL(size, 0)
FROM data
LEFT JOIN rope_length USING (tenant, hash)
`

	rows, err := s.DB.Query(ctx, q,
		req.Tenant, p, p+"/%", req.GetCursor().GetAfter(), when, listLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Avoid unnecessary allocation if we don't actually use the map.
	metaMap := make(map[string]string)
	ret := make([]*file.Meta, 0, listLimit)
	for rows.Next() {
		m := &file.Meta{Tenant: req.Tenant}
		var cTime, mTime time.Time

		if err := rows.Scan(
			&m.Path, &m.Version, &cTime, &metaMap, &mTime, &m.Size,
		); err != nil {
			return nil, err
		}
		m.CreatedAt = timestamppb.New(cTime)
		m.ModifiedAt = timestamppb.New(mTime)
		if len(metaMap) > 0 {
			m.Meta = metaMap
			metaMap = make(map[string]string)
		}
		ret = append(ret, m)
	}

	var cursor *file.Cursor
	if len(ret) == listLimit {
		cursor = &file.Cursor{
			After: ret[listLimit-1].Path,
			AsOf:  timestamppb.New(when),
		}
	}

	return &file.ListResponse{
		Files:  ret,
		Cursor: cursor,
	}, nil
}

// Retrieve implements file.FilesServer.
func (s *Server) Retrieve(
	ctx context.Context, req *file.RetrievalRequest,
) (*file.RetrievalResponse, error) {
	sn, ret, err := s.retrievePath(ctx, req.Tenant, req.Path, req.Version, req.ValidFor.AsDuration())
	if err != nil {
		return nil, err
	}
	return &file.RetrievalResponse{
		ExpiresAt: sn.ExpiresAt,
		GetPath:   ret,
	}, nil
}

// retrievePath cooks up a signed access path to retrieve the file.
func (s *Server) retrievePath(
	ctx context.Context, tID *tenant.ID, filePath string, version int64, validity time.Duration,
) (*session.Session, string, error) {
	parent := session.FromContext(ctx)
	sn := &session.Session{
		Capabilities: &capabilities.Capabilities{Read: true},
		PrincipalId:  parent.PrincipalId,
		Scope: &session.Scope{
			Kind: &session.Scope_OnLocation{
				OnLocation: &session.Location{
					TenantId: tID,
					Path:     filePath,
					Version:  version,
				}}},
	}
	now := time.Now()
	if validity > 0 {
		sn.ExpiresAt = timestamppb.New(now.Add(validity).Round(time.Second))
	}

	_, jwt, err := claims.Sign(now, sn, s.Config.SigningKeys[0])
	if err != nil {
		return nil, "", err
	}

	// Stuff the original filename into the path for friendly downloads.
	// The actual path will be picked out of the token.
	u := &url.URL{
		Path: path.Join("/_/v0/retrieve/", url.PathEscape(path.Base(filePath))),
		RawQuery: url.Values{
			"access_token": []string{jwt.Jwt},
		}.Encode(),
	}

	return sn, u.RequestURI(), nil
}
