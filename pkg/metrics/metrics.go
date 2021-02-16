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

// Package metrics provides a variety of wire bindings for the
// Prometheus client library.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/Mandala/go-log"
	"github.com/google/wire"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Set is used by wire.
var Set = wire.NewSet(
	ProvideFactory,
	ProvideInterceptor,
	ProvideMetricsHandler,
	ProvideWrapper,
	prometheus.NewPedanticRegistry,
	wire.Bind(new(prometheus.Gatherer), new(*prometheus.Registry)),
	wire.Bind(new(prometheus.Registerer), new(*prometheus.Registry)),
)

// Handler exports prometheus metrics.
type Handler http.Handler

// Wrapper will add metrics collection to the given handler.
type Wrapper func(h http.Handler, name string) http.Handler

// ProvideFactory is called by wire.
func ProvideFactory(r prometheus.Registerer) promauto.Factory {
	ret := promauto.With(r)

	start := float64(time.Now().Unix())
	ret.NewCounterFunc(prometheus.CounterOpts{
		Name: "start_time",
		Help: "the time at which the cacheroach process started",
	}, func() float64 { return start })

	return ret
}

// Interceptor provides methods for unary and streaming gRPC calls.
type Interceptor struct {
	reqSizes, respSizes, respTimes *prometheus.SummaryVec
}

// ProvideInterceptor is called by wire.
func ProvideInterceptor(
	auto promauto.Factory,
) *Interceptor {
	labels := []string{"code", "name"}
	return &Interceptor{
		reqSizes: auto.NewSummaryVec(prometheus.SummaryOpts{
			Name:       "rpc_request_bytes",
			Help:       "RPC request sizes",
			Objectives: map[float64]float64{0.5: 0.5, 0.9: 0.1, 0.99: 0.01},
		}, labels),
		respSizes: auto.NewSummaryVec(prometheus.SummaryOpts{
			Name:       "rpc_response_bytes",
			Help:       "RPC response sizes",
			Objectives: map[float64]float64{0.5: 0.5, 0.9: 0.1, 0.99: 0.01},
		}, labels),
		respTimes: auto.NewSummaryVec(prometheus.SummaryOpts{
			Name:       "rpc_response_seconds",
			Help:       "RPC response timing",
			Objectives: map[float64]float64{0.5: 0.5, 0.9: 0.1, 0.99: 0.01},
		}, labels),
	}
}

// Stream wraps a streaming gRPC call.
func (i *Interceptor) Stream(
	srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	start := time.Now()
	err := handler(srv, ss)

	if s, ok := status.FromError(err); ok {
		t := time.Since(start).Seconds()
		i.respTimes.WithLabelValues(s.Code().String(), info.FullMethod).Observe(t)
	}

	return err
}

// Unary wraps a unary gRPC call.
func (i *Interceptor) Unary(
	ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (interface{}, error) {
	reqSize := -1
	if msg, ok := req.(proto.Message); ok {
		reqSize = proto.Size(msg)
	}
	start := time.Now()
	ret, err := handler(ctx, req)
	t := time.Since(start).Seconds()

	code := codes.Unknown.String()
	if s, ok := status.FromError(err); ok {
		code = s.Code().String()
	}

	i.respTimes.WithLabelValues(code, info.FullMethod).Observe(t)
	if msg, ok := ret.(proto.Message); ok {
		s := proto.Size(msg)
		i.respSizes.WithLabelValues(code, info.FullMethod).Observe(float64(s))
	}
	if reqSize >= 0 {
		i.reqSizes.WithLabelValues(code, info.FullMethod).Observe(float64(reqSize))
	}

	return ret, err
}

// ProvideMetricsHandler is called by wire.
func ProvideMetricsHandler(
	l *log.Logger,
	g prometheus.Gatherer,
	r prometheus.Registerer,
) Handler {
	return promhttp.InstrumentMetricHandler(r,
		promhttp.HandlerFor(g, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
			ErrorHandling:     promhttp.ContinueOnError,
			ErrorLog:          promLogger{l},
			Registry:          r,
			Timeout:           30 * time.Second,
		}))
}

// ProvideWrapper is called by wire.
func ProvideWrapper(
	auto promauto.Factory,
) Wrapper {
	labels := []string{"code", "method", "name"}

	respTimes := auto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "http_response_seconds",
		Help:       "HTTP response timing",
		Objectives: map[float64]float64{0.5: 0.5, 0.9: 0.1, 0.99: 0.01},
	}, labels)

	reqSize := auto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "http_request_bytes",
		Help:       "HTTP request size",
		Objectives: map[float64]float64{0.5: 0.5, 0.9: 0.1, 0.99: 0.01},
	}, labels)

	respSize := auto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "http_response_bytes",
		Help:       "HTTP response size",
		Objectives: map[float64]float64{0.5: 0.5, 0.9: 0.1, 0.99: 0.01},
	}, labels)

	return func(h http.Handler, name string) http.Handler {
		l := prometheus.Labels{"name": name}
		h = promhttp.InstrumentHandlerResponseSize(respSize.MustCurryWith(l), h)
		h = promhttp.InstrumentHandlerDuration(respTimes.MustCurryWith(l), h)
		h = promhttp.InstrumentHandlerRequestSize(reqSize.MustCurryWith(l), h)
		return h
	}
}

type promLogger struct {
	*log.Logger
}

func (l promLogger) Println(args ...interface{}) {
	l.Warn(args...)
}
