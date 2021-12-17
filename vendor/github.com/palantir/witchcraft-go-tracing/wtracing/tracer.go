// Copyright (c) 2018 Palantir Technologies. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wtracing

import (
	"net"
)

type Tracer interface {
	StartSpan(name string, options ...SpanOption) Span
}

type TracerOption interface {
	apply(impl *TracerOptionImpl)
}

func FromTracerOptions(opts ...TracerOption) *TracerOptionImpl {
	impl := &TracerOptionImpl{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.apply(impl)
	}
	return impl
}

type tracerOptionFn func(impl *TracerOptionImpl)

func (t tracerOptionFn) apply(impl *TracerOptionImpl) {
	t(impl)
}

type TracerOptionImpl struct {
	Sampler       Sampler
	LocalEndpoint *Endpoint
}

type Sampler func(id uint64) bool

func WithSampler(sampler Sampler) TracerOption {
	return tracerOptionFn(func(impl *TracerOptionImpl) {
		impl.Sampler = sampler
	})
}

func WithLocalEndpoint(endpoint *Endpoint) TracerOption {
	return tracerOptionFn(func(impl *TracerOptionImpl) {
		impl.LocalEndpoint = endpoint
	})
}

type Endpoint struct {
	ServiceName string
	IPv4        net.IP
	IPv6        net.IP
	Port        uint16
}
