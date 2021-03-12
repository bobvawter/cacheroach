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

//+build tools

package main

import (
	_ "github.com/google/wire/cmd/wire"
	_ "github.com/hhatto/gocloc/cmd/gocloc"
	_ "golang.org/x/lint/golint"
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "honnef.co/go/tools/cmd/staticcheck"
)

//go:generate protoc --go_out=./api/ --go_opt=module=github.com/bobvawter/cacheroach/api --go-grpc_out=./api/ --go-grpc_opt=module=github.com/bobvawter/cacheroach/api -I ./api/ capabilities.proto diag.proto file.proto principal.proto session.proto tenant.proto token.proto upload.proto vhost.proto
//go:generate go run github.com/google/wire/cmd/wire gen ./pkg/...
//go:generate go run ./pkg/cmd/gendoc ./doc/
