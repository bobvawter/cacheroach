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

package cli

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sync"

	"github.com/bobvawter/cacheroach/api/file"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/upload"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"
)

type work struct {
	localPath  string
	stat       os.FileInfo
	remotePath string
}

func (c *CLI) file() *cobra.Command {
	var tntString string
	var tnt *tenant.ID
	top := &cobra.Command{
		Use:   "file",
		Short: "file operations",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if c.DefaultTenant != nil {
				tnt = c.DefaultTenant
			}
			var err error
			if tntString != "" {
				tnt, err = tenant.ParseID(tntString)
				if err != nil {
					return err
				}
			}
			if tnt == nil {
				tnt = c.Config.Session.GetScope().GetOnLocation().GetTenantId()
			}
			if tnt == nil {
				return errors.New("--tenant required")
			}
			return nil
		},
	}
	top.PersistentFlags().StringVarP(&tntString, "tenant", "t", tntString,
		"sent the tenant to use if one is not present in the logged-in scope")

	var getOut string
	get := &cobra.Command{
		Use:   "get <path> [ ... ]",
		Short: "download files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			stat, _ := os.Stat(getOut)
			outExists := stat != nil
			outIsDir := false
			if stat != nil && stat.IsDir() {
				outIsDir = true
			}

			outFiles := make([]string, len(args))
			if len(args) == 1 {
				if outExists && outIsDir {
					outFiles[0] = filepath.Join(stat.Name(), path.Base(args[0]))
				} else {
					outFiles[0] = getOut
				}
			} else if outExists && !outIsDir {
				return errors.New("multiple files requested, but --out is not a directory")
			} else {
				for i := range args {
					outFiles[i] = filepath.Join(getOut, path.Base(args[i]))
				}
			}

			conn, err := c.conn(cmd.Context())
			if err != nil {
				return err
			}
			fs := file.NewFilesClient(conn)

			out := newTabs()
			defer out.Close()
			out.Printf("Remote\tLocal\tStatus\n")

			var ret error
			for i := range args {
				if err := c.get(cmd.Context(), fs, tnt, outFiles[i], args[i]); err == nil {
					out.Printf("%s\t%s\tOK\n", args[i], outFiles[i])
				} else {
					out.Printf("%s\t%s\t%v\n", args[i], outFiles[i], err)
					ret = err
				}
			}

			return ret
		},
	}
	get.Flags().StringVarP(&getOut, "out", "o", ".",
		"a local file or directory to write the download(s) to")

	fetchHeaders := make(map[string]string)
	var fetchMethod string
	fetch := &cobra.Command{
		Use:   "fetch <cacheroach path> <remote URL> ...",
		Short: "execute an HTTP request from the server",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			remoteBase := args[0]
			args = args[1:]
			if !strings.HasPrefix(remoteBase, "/") {
				return errors.New("the remote path must start with /")
			}
			if !strings.HasSuffix(remoteBase, "/") {
				return errors.New(
					"the target for an upload must " +
						"end in a / to avoid ambiguous behavior")
			}

			conn, err := c.conn(ctx)
			if err != nil {
				return err
			}
			up := upload.NewUploadsClient(conn)

			out := newTabs()
			defer out.Close()
			out.Printf("Path\tURL\tCode\tMessage\n")

			for i := range args {
				remotePath := path.Join(remoteBase, path.Base(args[i]))
				resp, err := up.Fetch(ctx, &upload.FetchRequest{
					Tenant:        tnt,
					Path:          remotePath,
					RemoteUrl:     args[i],
					RemoteHeaders: fetchHeaders,
					RemoteMethod:  fetchMethod,
				})
				if err == nil {
					out.Printf("%s\t%s\t%d\t%s\n", remotePath, args[i], resp.RemoteHttpCode, resp.RemoteHttpMessage)
				} else {
					out.Printf("%s\t%s\t%d\t%s\n", remotePath, args[i], 0, err.Error())
				}
			}
			return nil
		},
	}
	fetch.Flags().StringToStringVar(&fetchHeaders, "headers", nil, "remote request headers")
	fetch.Flags().StringVar(&fetchMethod, "method", "GET", "the http method to use")

	wide := false
	ls := &cobra.Command{
		Use:   "ls <remote path> ...",
		Short: "list remote files",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"/"}
			}

			conn, err := c.conn(cmd.Context())
			if err != nil {
				return err
			}
			fs := file.NewFilesClient(conn)

			out := newTabs()
			defer out.Close()
			if wide {
				out.Printf("Path\tSize\tVersion\tCTime\tMTime\n")
			}

			for _, path := range args {
				req := &file.ListRequest{
					Tenant: tnt,
					Path:   path,
				}
				for {
					resp, err := fs.List(cmd.Context(), req)
					if err != nil {
						return err
					}
					for _, meta := range resp.Files {

						if wide {
							out.Printf("%s\t%d\t%d\t%s\t%s\n",
								meta.Path, meta.Size, meta.Version,
								meta.CreatedAt.AsTime().Format(time.Stamp),
								meta.ModifiedAt.AsTime().Format(time.Stamp))
						} else {
							out.Printf("%s\n", meta.Path)
						}
					}
					req.Cursor = resp.Cursor
					if req.Cursor == nil {
						break
					}
				}
			}
			return nil
		},
	}
	ls.Flags().BoolVarP(&wide, "wide", "w", false, "print more data")

	var recurse bool
	var parallelism int
	put := &cobra.Command{
		Use:   "put <remote path> <local file or dir> ...",
		Short: "upload files",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			remotePath := args[0]
			args = args[1:]
			if !strings.HasPrefix(remotePath, "/") {
				return errors.New("the remote path must start with /")
			}
			if !strings.HasSuffix(remotePath, "/") {
				return errors.New(
					"the target for an upload must " +
						"end in a / to avoid ambiguous behavior")
			}

			// We may not be getting called from an actual shell, so
			// let's glob-expand the inputs.
			var localFiles []string
			for i := range args {
				expanded, err := filepath.Glob(args[i])
				if err != nil {
					return err
				}
				localFiles = append(localFiles, expanded...)
			}

			if len(localFiles) == 0 {
				c.logger.Warn("no local files matched")
				return nil
			}

			conn, err := c.conn(ctx)
			if err != nil {
				return err
			}
			up := upload.NewUploadsClient(conn)

			var muOut sync.Mutex
			out := newTabs()
			defer out.Close()
			out.Printf("Local\tRemote\tStatus\n")

			ch := make(chan *work)
			var ret error
			var wg sync.WaitGroup

			for i := 0; i < parallelism; i++ {
				wg.Add(1)
				go func() {
					for w := range ch {
						err := c.put(ctx, up, tnt, w)
						muOut.Lock()
						if err == nil {
							c.logger.Infof("uploaded %s -> %s", w.localPath, w.remotePath)
							out.Printf("%s\t%s\tOK\n", w.localPath, w.remotePath)
						} else {
							c.logger.Warnf("upload failed %s -> %s: %v", w.localPath, w.remotePath, err)
							ret = err
							out.Printf("%s\t%s\t%v\n", w.localPath, w.remotePath, err)
						}
						muOut.Unlock()
					}
					wg.Done()
				}()
			}

			for i := range localFiles {
				if err := c.expand(ctx, localFiles[i], remotePath, recurse, ch); err != nil {
					return err
				}
			}

			close(ch)
			wg.Wait()

			return ret
		},
	}
	put.Flags().IntVarP(&parallelism, "parallelism", "p", 4, "the number of concurrent uploads")
	put.Flags().BoolVarP(&recurse, "recurse", "r", false, "recursively upload directories")

	rm := &cobra.Command{
		Use:   "rm <remote path> ...",
		Short: "mark files for deletion",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := c.conn(cmd.Context())
			if err != nil {
				return err
			}

			out := newTabs()
			defer out.Close()
			out.Printf("Path\tStatus\n")

			fs := file.NewFilesClient(conn)
			for i := range args {
				_, err := fs.Delete(cmd.Context(), &file.DeleteRequest{
					Tenant: tnt,
					Path:   args[i],
				})
				if err == nil {
					out.Printf("%s\tOK\n", args[i])
				} else {
					out.Printf("%s\t%v\n", args[i], err)
				}
			}
			return nil
		},
	}

	var signDuration time.Duration
	sign := &cobra.Command{
		Use:   "sign <path> [ ... ]",
		Short: "generate signed access URLs",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			conn, err := c.conn(ctx)
			if err != nil {
				return err
			}
			fs := file.NewFilesClient(conn)

			out := newTabs()
			defer out.Close()
			out.Printf("Path\tURL\n")

			for i := range args {
				retrieval, err := fs.Retrieve(ctx, &file.RetrievalRequest{
					Path:     args[i],
					Tenant:   tnt,
					ValidFor: durationpb.New(signDuration),
				})
				if err != nil {
					return errors.Wrap(err, args[i])
				}
				c.logger.Tracef("created download URI: %s", retrieval.GetUri)

				u, err := url.ParseRequestURI(retrieval.GetUri)
				if err != nil {
					return errors.Wrap(err, args[i])
				}
				if c.Insecure {
					u.Scheme = "http"
				} else {
					u.Scheme = "https"
				}
				u.Host = c.Host

				out.Printf("%s\t%s\n", args[i], u)
			}

			return nil
		},
	}
	sign.Flags().DurationVar(&signDuration, "validity", 24*time.Hour,
		"the length of time the link will be valid for")

	top.AddCommand(
		get,
		fetch,
		ls,
		put,
		rm,
		sign,
	)

	return top
}

func (c *CLI) get(
	ctx context.Context, fs file.FilesClient, tnt *tenant.ID,
	localFile, remotePath string,
) error {
	retrieval, err := fs.Retrieve(ctx, &file.RetrievalRequest{
		Path:     remotePath,
		Tenant:   tnt,
		ValidFor: durationpb.New(time.Minute),
	})
	if err != nil {
		return err
	}
	c.logger.Tracef("created download URL: %s", retrieval.GetUri)

	u, err := url.ParseRequestURI(retrieval.GetUri)
	if err != nil {
		return err
	}
	u.Host = c.Host
	if c.Insecure {
		u.Scheme = "http"
	} else {
		u.Scheme = "https"
	}

	resp, err := http.DefaultClient.Do(&http.Request{URL: u, Method: http.MethodGet})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}

	var out io.WriteCloser
	if localFile == "-" {
		out = os.Stdout
	} else {
		if err := os.MkdirAll(filepath.Dir(localFile), 0755); err != nil {
			return err
		}
		out, err = os.OpenFile(localFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
	}
	defer out.Close()
	n, err := io.Copy(out, resp.Body)
	if err == nil {
		c.logger.Infof("wrote %d bytes to %s", n, localFile)
	}
	return err
}

func (c *CLI) put(
	ctx context.Context, up upload.UploadsClient, tnt *tenant.ID, w *work,
) error {

	// Can't mmap a 0-length file.
	var data []byte
	if w.stat.Size() > 0 {
		f, err := os.Open(w.localPath)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err = syscall.Mmap(int(f.Fd()), 0, int(w.stat.Size()),
			syscall.PROT_READ, syscall.MAP_FILE|syscall.MAP_PRIVATE)
		if err != nil {
			return err
		}
		defer syscall.Munmap(data)
		c.logger.Tracef("mmapped %s", f.Name())
	}
	req := &upload.BeginRequest{
		Path:   w.remotePath,
		Tenant: tnt,
	}
	if w.stat.Size() == 0 {
		req.Committed = &upload.BeginRequest_Empty{Empty: true}
	} else if w.stat.Size() < 1024*1024 {
		req.Committed = &upload.BeginRequest_Contents{Contents: data}
	}
	resp, err := up.Begin(ctx, req)
	if err != nil {
		return err
	}
	if resp.Committed {
		c.logger.Tracef("committed: %s", req.Path)
		return nil
	}
	c.logger.Tracef("upload state: %s", resp.State)

	chunk := int64(resp.MaxChunkSize)
	offset := int64(0)
	remaining := w.stat.Size()
	state := resp.State
	retry := true

	for remaining > 0 {
		if chunk > remaining {
			chunk = remaining
		}

		resp, err := up.Transfer(ctx,
			&upload.TransferRequest{
				Data:  data[offset : offset+chunk],
				State: state,
			})
		if err != nil {
			if retry {
				retry = false
				c.logger.Warnf("could not transfer chunk; will retry: %v", err)
				continue
			} else {
				return err
			}
		}
		offset += chunk
		remaining -= chunk
		retry = true
		state = resp.State
		c.logger.Tracef("uploaded chunk: %s", state)
	}

	for retry {
		_, err = up.Commit(ctx, &upload.CommitRequest{State: state})
		if err == nil {
			break
		}
		c.logger.Warnf("could not commit; will retry: %v", err)
		time.Sleep(time.Second)
		retry = false
	}
	return nil
}

// expand generates work items from some number of local files or
// directories. If recurse is false, directories will be ignored.
func (c *CLI) expand(
	ctx context.Context, localBase, remoteBase string, recurse bool, ch chan<- *work,
) error {
	return filepath.Walk(localBase, func(localFile string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		stat, err := os.Stat(localFile)
		if err != nil {
			return errors.Wrap(err, localFile)
		}

		if stat.IsDir() {
			if !recurse {
				c.logger.Tracef("no recurse; ignoring %s", stat.Name())
				return filepath.SkipDir
			}
			return nil
		}
		if !stat.Mode().IsRegular() {
			c.logger.Tracef("ignoring %s", stat.Name())
			return nil
		}
		relPath := ""
		if localBase == localFile {
			relPath = localFile
		} else {
			relPath, err = filepath.Rel(localBase, localFile)
			if err != nil {
				return errors.Wrap(err, localFile)
			}
		}
		w := &work{
			localPath:  localFile,
			stat:       stat,
			remotePath: path.Join(remoteBase, filepath.ToSlash(relPath)),
		}
		c.logger.Tracef("upload %s -> %s", w.localPath, w.remotePath)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- w:
		}

		return nil
	})
}
