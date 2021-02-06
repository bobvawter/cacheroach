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

// Package gcloud contains utility methods when deploying in
// Google Cloud Platform environments.
package gcloud

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/Mandala/go-log"
	"github.com/pkg/errors"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// Config controls the gcloud secret-download process.
type Config struct {
	Name string // The GCP secret name.
	Out  string // The directory to unpack the secret into.
}

// Download retrieves the named secret and unpacks it.
func (c *Config) Download(ctx context.Context, logger *log.Logger) error {
	if c.Name == "" || c.Out == "" {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return err
	}
	logger.Trace("connected to gcloud Secret Manager API")

	resp, err := client.AccessSecretVersion(ctx,
		&secretmanagerpb.AccessSecretVersionRequest{
			Name: c.Name,
		})
	if err != nil {
		return err
	}
	logger.Tracef("retrieved secret %s", resp.Name)

	gzReader, err := gzip.NewReader(bytes.NewReader(resp.GetPayload().GetData()))
	if err != nil {
		return err
	}

	t := tar.NewReader(gzReader)
	for {
		h, err := t.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}

		f, err := os.OpenFile(filepath.Join(c.Out, h.Name), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, t); err != nil {
			return err
		}
		_ = f.Close()
		logger.Infof("wrote %s", f.Name())
	}
	return nil
}
