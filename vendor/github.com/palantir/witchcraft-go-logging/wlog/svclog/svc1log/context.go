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

package svc1log

import (
	"context"

	"github.com/palantir/witchcraft-go-logging/wlog"
	wloginternal "github.com/palantir/witchcraft-go-logging/wlog/internal"
	wparams "github.com/palantir/witchcraft-go-params"
	"github.com/palantir/witchcraft-go-tracing/wtracing"
)

type svc1LogContextKeyType string

const contextKey = svc1LogContextKeyType(TypeValue)

// WithLogger returns a copy of the provided context with the provided Logger included as a value. This operation will
// replace any logger that was previously set on the context (along with all parameters that may have been set on the
// logger).
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, contextKey, logger)
}

// WithLoggerParams returns a copy of the provided context whose logger is configured with the provided parameters. If
// no parameters are provided, the original context is returned unmodified. If the provided context did not have a
// logger set on it, the returned context will contain the default logger configured with the provided parameters. If
// any of the provided parameters set safe or unsafe values, the returned context will also have those values set on it
// using the wparams.ContextWithSafeAndUnsafeParams function.
func WithLoggerParams(ctx context.Context, params ...Param) context.Context {
	if len(params) == 0 {
		return ctx
	}
	// if the provided params set any safe or unsafe values, set those as wparams on the context
	if safeParams, unsafeParams := safeAndUnsafeParamsFromParams(params); len(safeParams) > 0 || len(unsafeParams) > 0 {
		ctx = wparams.ContextWithSafeAndUnsafeParams(ctx, safeParams, unsafeParams)
	}
	return WithLogger(ctx, WithParams(loggerFromContext(ctx), params...))
}

// FromContext returns the Logger stored in the provided context. If no logger is set on the context, returns the logger
// created by calling DefaultLogger. If the context contains a TraceID set using wtracing, the returned logger has that
// TraceID set on it as a parameter. Any safe or unsafe parameters stored on the context using wparams are also set as
// parameters on the returned logger.
func FromContext(ctx context.Context) Logger {
	logger := loggerFromContext(ctx)
	var params []Param
	if paramStorer := wparams.ParamStorerFromContext(ctx); paramStorer != nil && (len(paramStorer.SafeParams()) > 0 || len(paramStorer.UnsafeParams()) > 0) {
		params = append(params, Params(paramStorer))
	}
	if uid := wloginternal.IDFromContext(ctx, wloginternal.UIDKey); uid != nil {
		params = append(params, UID(*uid))
	}
	if sid := wloginternal.IDFromContext(ctx, wloginternal.SIDKey); sid != nil {
		params = append(params, SID(*sid))
	}
	if tokenID := wloginternal.IDFromContext(ctx, wloginternal.TokenIDKey); tokenID != nil {
		params = append(params, TokenID(*tokenID))
	}
	if traceID := wtracing.TraceIDFromContext(ctx); traceID != "" {
		params = append(params, TraceID(string(traceID)))
	}
	return WithParams(logger, params...)
}

func safeAndUnsafeParamsFromParams(params []Param) (safe map[string]interface{}, unsafe map[string]interface{}) {
	logEntry := wlog.NewMapLogEntry()
	for _, currParam := range params {
		currParam.apply(logEntry)
	}
	return logEntry.AnyMapValues()[ParamsKey], logEntry.AnyMapValues()[wlog.UnsafeParamsKey]
}

// loggerFromContext returns the logger stored in the provided context. If no logger is set on the context, returns the
// logger created by calling DefaultLogger.
func loggerFromContext(ctx context.Context) Logger {
	if logger, ok := ctx.Value(contextKey).(Logger); ok {
		return logger
	}
	return defaultLoggerCreator()
}
