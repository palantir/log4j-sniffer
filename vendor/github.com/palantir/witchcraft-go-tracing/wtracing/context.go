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
	"context"
)

type tracerContextKeyType string

const tracerContextKey = tracerContextKeyType("wtracing.tracer")

// ContextWithTracer returns a copy of the provided context with the provided Tracer included as a value.
func ContextWithTracer(ctx context.Context, tracer Tracer) context.Context {
	return context.WithValue(ctx, tracerContextKey, tracer)
}

// TracerFromContext returns the Tracer stored in the provided context. Returns nil if no Tracer is stored in the
// context.
func TracerFromContext(ctx context.Context) Tracer {
	if tracer, ok := ctx.Value(tracerContextKey).(Tracer); ok {
		return tracer
	}
	return nil
}

type spanContextKeyType string

const spanContextKey = spanContextKeyType("wtracing.span")

// ContextWithSpan returns a copy of the provided context with the provided span set on it.
func ContextWithSpan(ctx context.Context, s Span) context.Context {
	return context.WithValue(ctx, spanContextKey, s)
}

// SpanFromContext returns the span stored in the provided context, or nil if no span is stored in the context.
func SpanFromContext(ctx context.Context) Span {
	if s, ok := ctx.Value(spanContextKey).(Span); ok {
		return s
	}
	return nil
}

// StartSpanFromContext starts a new span with the provided parameters using the provided tracer and the span
// information in the provided context. If the context contains a span, the new span will be configured to be a child
// span of that span (unless any of the user-provided span options overrides this). Returns the newly started span and a
// copy of the provided context that has the new span set as its current span. Returns a nil span if the provided tracer
// is nil.
//
// This function does not read or set the tracer on the provided context. To start a span new span from the tracer set
// on a context, call StartSpanFromContext(TracerFromContext(ctx), ctx, spanName, spanOptions).
func StartSpanFromContext(ctx context.Context, tracer Tracer, spanName string, spanOptions ...SpanOption) (Span, context.Context) {
	if tracer == nil {
		return nil, ctx
	}
	if spanInCtx := SpanFromContext(ctx); spanInCtx != nil {
		spanOptions = append([]SpanOption{WithParent(spanInCtx)}, spanOptions...)
	}
	newSpan := tracer.StartSpan(spanName, spanOptions...)
	newCtx := ContextWithSpan(ctx, newSpan)
	return newSpan, newCtx
}

// StartSpanFromTracerInContext starts a new span with the provided parameters using the tracer and the span information
// in the provided context. If the context contains a span, the new span will be configured to be a child span of that
// span (unless any of the user-provided span options overrides this). Returns the newly started span and a copy of the
// provided context that has the new span set as its current span.
//
// If the context does not contain a tracer, returns a no-op Span and an unmodified version of the provided context. The
// span returned by this function is always non-nil.
func StartSpanFromTracerInContext(ctx context.Context, spanName string, spanOptions ...SpanOption) (Span, context.Context) {
	tracer := TracerFromContext(ctx)
	if tracer == nil {
		return &noopSpan{}, ctx
	}
	if spanInCtx := SpanFromContext(ctx); spanInCtx != nil {
		spanOptions = append([]SpanOption{WithParent(spanInCtx)}, spanOptions...)
	}
	newSpan := tracer.StartSpan(spanName, spanOptions...)
	newCtx := ContextWithSpan(ctx, newSpan)
	return newSpan, newCtx
}

type noopSpan struct{}

func (noopSpan) Context() SpanContext {
	return SpanContext{}
}

func (noopSpan) Finish() {}

func (noopSpan) Tag(string, string) {}

// TraceIDFromContext returns the traceId associated with the span stored in the provided context. Returns an empty
// string if no span is stored in the context.
func TraceIDFromContext(ctx context.Context) TraceID {
	if span := SpanFromContext(ctx); span != nil {
		return span.Context().TraceID
	}
	return ""
}
