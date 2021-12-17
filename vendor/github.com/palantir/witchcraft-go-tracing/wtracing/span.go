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
	"time"
)

// TraceID and SpanID are identifiers for the trace and span. Represented as hex strings.
type TraceID string
type SpanID string

type Span interface {
	Context() SpanContext

	// Tag sets Tag with given key and value to the Span. If key already exists in
	// the Span the value will be overridden except for error tags where the first
	// value is persisted.
	Tag(key string, value string)

	// Finish the Span and send to Reporter.
	Finish()
}

type SpanModel struct {
	SpanContext

	Name           string
	Kind           Kind
	Timestamp      time.Time
	Duration       time.Duration
	LocalEndpoint  *Endpoint
	RemoteEndpoint *Endpoint
	Tags           map[string]string
}

type SpanContext struct {
	TraceID  TraceID
	ID       SpanID
	ParentID *SpanID
	Debug    bool
	Sampled  *bool
	Err      error
}

func FromSpanOptions(opts ...SpanOption) *SpanOptionImpl {
	impl := &SpanOptionImpl{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.apply(impl)
	}
	return impl
}

type SpanOption interface {
	apply(impl *SpanOptionImpl)
}

type spanOptionFn func(impl *SpanOptionImpl)

func (t spanOptionFn) apply(impl *SpanOptionImpl) {
	t(impl)
}

type SpanOptionImpl struct {
	RemoteEndpoint *Endpoint
	ParentSpan     *SpanContext
	Kind           Kind
	Tags           map[string]string
}

func WithKind(kind Kind) SpanOption {
	return spanOptionFn(func(impl *SpanOptionImpl) {
		impl.Kind = kind
	})
}

// WithParent sets the parent SpanContext to be the context of the specified span. If the provided span is nil, the
// parent span context is explicitly set to be nil (indicating that the created span is a root span).
func WithParent(parent Span) SpanOption {
	var parentCtx SpanContext
	if parent != nil {
		parentCtx = parent.Context()
	}
	return WithParentSpanContext(parentCtx)
}

// WithParentSpanContext sets the parent span context to be the specified span context. If the provided context is valid
// (TraceID and SpanID are set), the new span will use the same TraceID and set its ParentID to be the SpanID. If the
// TraceID is set but the SpanID is not, the new span will be a root span and its TraceId and SpanID will both be the
// same value as the TraceID in the provided context. The debug and sampled values are always inherited (regardless of
// the other fields).
func WithParentSpanContext(parentCtx SpanContext) SpanOption {
	return spanOptionFn(func(impl *SpanOptionImpl) {
		impl.ParentSpan = &parentCtx
	})
}

func WithRemoteEndpoint(endpoint *Endpoint) SpanOption {
	return spanOptionFn(func(impl *SpanOptionImpl) {
		impl.RemoteEndpoint = endpoint
	})
}

// WithSpanTag adds the tag indexed by name with the value specified to the set of tags defined for this span.
// If the same name is seen multiple times the most recent will prevail.
func WithSpanTag(name, value string) SpanOption {
	return spanOptionFn(func(impl *SpanOptionImpl) {
		if impl.Tags == nil {
			impl.Tags = make(map[string]string)
		}
		impl.Tags[name] = value
	})
}
