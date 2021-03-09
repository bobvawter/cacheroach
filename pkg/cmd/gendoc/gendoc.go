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

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Mandala/go-log"
	"github.com/blushft/go-diagrams/diagram"
	"github.com/blushft/go-diagrams/nodes/apps"
	"github.com/blushft/go-diagrams/nodes/aws"
	"github.com/blushft/go-diagrams/nodes/azure"
	"github.com/blushft/go-diagrams/nodes/gcp"
	"github.com/blushft/go-diagrams/nodes/generic"
	"github.com/bobvawter/cacheroach/pkg/cmd/root"
	"github.com/spf13/cobra/doc"
)

var out string

// Auto-generate Cobra documentation and other diagrams.
func main() {
	logger := log.New(os.Stderr)
	if len(os.Args) != 2 {
		logger.Error("must specify output directory as sole argument")
		os.Exit(1)
	}
	out = filepath.Clean(os.Args[1])
	x := root.Command(logger)
	x.DisableAutoGenTag = true
	if err := doc.GenMarkdownTree(x, out); err != nil {
		logger.Errorf("could not generate: %v", err)
	}
	if err := heroDiagram(context.Background()); err != nil {
		logger.Errorf("could not generate: %v", err)
	}
}

type anchoredGroup struct {
	// A node to use for edges.
	anchor *diagram.Node
	// The group to use as a target of an lhead or ltail edge attribute.
	group *diagram.Group
}

func (g *anchoredGroup) Anchor() string {
	return g.anchor.ID()
}

func (g *anchoredGroup) Group() string {
	return g.group.ID()
}

func newCRDB(name string) *anchoredGroup {
	// The prefix "cluster_" is meaningful to graphviz.
	g := diagram.NewGroup("crdb_" + name)
	g.Label("Local CockroachDB Cluster")

	n1 := apps.Database.Cockroachdb(diagram.NodeLabel("cockroach"))
	n2 := apps.Database.Cockroachdb(diagram.NodeLabel("cockroach"))
	g.Connect(n1, n2, diagram.Bidirectional())
	return &anchoredGroup{n1, g}
}

type region struct {
	anchoredGroup
	crdb *anchoredGroup
}

func newRegion(name string) *region {
	r := &region{
		anchoredGroup: anchoredGroup{
			anchor: generic.Storage.Storage().Label("Cacheroach"),
			group:  diagram.NewGroup("region_" + name),
		},
		crdb: newCRDB(name),
	}

	r.group.Group(r.crdb.group)
	r.group.Add(r.anchor)
	r.group.ConnectByID(r.Anchor(), r.crdb.Anchor(), func(o *diagram.EdgeOptions) {
		o.Attributes["lhead"] = r.crdb.Group()
	})

	return r
}

func heroDiagram(ctx context.Context) error {
	return render(ctx, "hero", "hero.png", func(ctx context.Context, d *diagram.Diagram) error {
		r1 := newRegion("r1")
		r1.group.Label("Cloud Provider A")
		app1 := aws.Compute.Ec2Rounded().Label("App")
		r1.group.Connect(app1, r1.anchor)

		r2 := newRegion("r2")
		r2.group.Label("Cloud Provider G")
		app2 := gcp.Compute.KubernetesEngine().Label("App")
		r2.group.Connect(app2, r2.anchor)

		r3 := newRegion("r3")
		r3.group.Label("Cloud Provider Z")
		app3 := azure.Compute.Vm().Label("App")
		r3.group.Connect(app3, r3.anchor)

		d.Group(r1.group)
		d.Group(r2.group)
		d.Group(r3.group)

		d.Connect(r1.crdb.anchor, r2.crdb.anchor, diagram.Bidirectional(), func(o *diagram.EdgeOptions) {
			o.Attributes["constraint"] = "false"
			o.Attributes["ltail"] = r1.crdb.Group()
			o.Attributes["lhead"] = r2.crdb.Group()
		})
		d.Connect(r1.crdb.anchor, r3.crdb.anchor, diagram.Bidirectional(), func(o *diagram.EdgeOptions) {
			o.Attributes["constraint"] = "false"
			o.Attributes["ltail"] = r1.crdb.Group()
			o.Attributes["lhead"] = r3.crdb.Group()
		})
		d.Connect(r2.crdb.anchor, r3.crdb.anchor, diagram.Bidirectional(), func(o *diagram.EdgeOptions) {
			o.Attributes["constraint"] = "false"
			o.Attributes["ltail"] = r2.crdb.Group()
			o.Attributes["lhead"] = r3.crdb.Group()
		})

		users := apps.Client.Users().Label("Users")
		d.Connect(users, app1)
		d.Connect(users, app2)
		d.Connect(users, app3)

		return nil
	})
}

// The go-diagram library is opinionated about where its output goes
// so we need to do some work in order to make it usable here.
func render(
	ctx context.Context,
	name, filename string,
	fn func(ctx context.Context, d *diagram.Diagram) error,
) error {
	tmp, err := os.MkdirTemp("", "gendoc")
	if err != nil {
		return err
	}
	tmp = filepath.Join(tmp, "diagram")

	filename, err = filepath.Abs(filepath.Join(out, filename))
	if err != nil {
		return err
	}

	d, err := diagram.New(
		diagram.Filename(name),
		func(o *diagram.Options) {
			// This actually overrides the output directory.
			o.Name = tmp
			o.Attributes["compound"] = "true"
		})

	if err != nil {
		return err
	}
	if err := fn(ctx, d); err != nil {
		return err
	}
	if err := d.Render(); err != nil {
		return err
	}

	cmd := exec.CommandContext(
		ctx,
		"dot",
		"-Tpng",
		"-o"+filename,
		name+".dot",
	)
	cmd.Dir = tmp
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}
