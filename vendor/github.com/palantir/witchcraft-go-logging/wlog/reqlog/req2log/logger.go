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

package req2log

import (
	"io"
	"net/http"
	"time"

	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog/extractor"
)

const (
	TypeValue = "request.2"

	methodKey       = "method"
	protocolKey     = "protocol"
	pathKey         = "path"
	paramsKey       = "params"
	statusKey       = "status"
	requestSizeKey  = "requestSize"
	responseSizeKey = "responseSize"
	durationKey     = "duration"
	traceIDKey      = wlog.TraceIDKey
)

// Logger creates a request log entry based on the provided information.
type Logger interface {
	Request(req Request)

	RequestParamPerms
}

type RequestParamPerms interface {
	PathParamPerms() ParamPerms
	QueryParamPerms() ParamPerms
	HeaderParamPerms() ParamPerms
}

// Request represents an HTTP request that has been (or is about to be) completed. Contains information on the request
// such as the request itself, the status code of the response, etc.
type Request struct {
	// Request is the *http.Request associated with the event.
	Request *http.Request
	// RouteInfo contains the path template and path parameter values for the request.
	RouteInfo RouteInfo
	// ResponseStatus is the status code of the response to the request.
	ResponseStatus int
	// ResponseSize is the size of the response to the request.
	ResponseSize int64
	// Duration is the total time it took to process the request.
	Duration time.Duration
	// PathParamPerms determines the path parameters that are safe and forbidden for logging.
	PathParamPerms ParamPerms
	// QueryParamPerms determines the query parameters that are safe and forbidden for logging.
	QueryParamPerms ParamPerms
	// HeaderParamPerms determines the header parameters that are safe and forbidden for logging.
	HeaderParamPerms ParamPerms
}

type RouteInfo struct {
	Template   string
	PathParams map[string]string
}

func New(w io.Writer, params ...LoggerCreatorParam) Logger {
	return NewFromCreator(w, wlog.DefaultLoggerProvider().NewLogger, params...)
}

func NewFromCreator(w io.Writer, creator wlog.LoggerCreator, params ...LoggerCreatorParam) Logger {
	loggerBuilder := &defaultLoggerBuilder{
		loggerCreator: creator,
		idsExtractor:  extractor.NewDefaultIDsExtractor(),
	}
	for _, p := range params {
		p.Apply(loggerBuilder)
	}
	return loggerBuilder.build(w)
}

type LoggerBuilder interface {
	LoggerCreator(creator wlog.LoggerCreator)
	IdsExtractor(idsExtractor extractor.IDsFromRequest)

	SafePathParams(safePathParams []string)
	ForbiddenPathParams(forbiddenPathParams []string)

	SafeQueryParams(safeQueryParams []string)
	ForbiddenQueryParams(forbiddenQueryParams []string)

	SafeHeaderParams(safeHeaderParams []string)
	ForbiddenHeaderParams(forbiddenHeaderParams []string)
}

type defaultLoggerBuilder struct {
	loggerCreator wlog.LoggerCreator
	idsExtractor  extractor.IDsFromRequest

	safePathParams      []string
	forbiddenPathParams []string

	safeQueryParams      []string
	forbiddenQueryParams []string

	safeHeaderParams      []string
	forbiddenHeaderParams []string
}

func (b *defaultLoggerBuilder) LoggerCreator(creator wlog.LoggerCreator) {
	b.loggerCreator = creator
}

func (b *defaultLoggerBuilder) IdsExtractor(idsExtractor extractor.IDsFromRequest) {
	b.idsExtractor = idsExtractor
}

func (b *defaultLoggerBuilder) SafePathParams(safePathParams []string) {
	b.safePathParams = append(b.safePathParams, safePathParams...)
}

func (b *defaultLoggerBuilder) ForbiddenPathParams(forbiddenPathParams []string) {
	b.forbiddenPathParams = append(b.forbiddenPathParams, forbiddenPathParams...)
}

func (b *defaultLoggerBuilder) SafeQueryParams(safeQueryParams []string) {
	b.safeQueryParams = append(b.safeQueryParams, safeQueryParams...)
}

func (b *defaultLoggerBuilder) ForbiddenQueryParams(forbiddenQueryParams []string) {
	b.forbiddenQueryParams = append(b.forbiddenQueryParams, forbiddenQueryParams...)
}

func (b *defaultLoggerBuilder) SafeHeaderParams(safeHeaderParams []string) {
	b.safeHeaderParams = append(b.safeHeaderParams, safeHeaderParams...)
}

func (b *defaultLoggerBuilder) ForbiddenHeaderParams(forbiddenHeaderParams []string) {
	b.forbiddenHeaderParams = append(b.forbiddenHeaderParams, forbiddenHeaderParams...)
}

func (b *defaultLoggerBuilder) build(w io.Writer) *defaultLogger {
	defaultParams := DefaultRequestParamPerms()
	return &defaultLogger{
		logger:           b.loggerCreator(w),
		idsExtractor:     b.idsExtractor,
		pathParamPerms:   CombinedParamPerms(defaultParams.PathParamPerms(), NewParamPerms(b.safePathParams, b.forbiddenPathParams)),
		queryParamPerms:  CombinedParamPerms(defaultParams.QueryParamPerms(), NewParamPerms(b.safeQueryParams, b.forbiddenQueryParams)),
		headerParamPerms: CombinedParamPerms(defaultParams.HeaderParamPerms(), NewParamPerms(b.safeHeaderParams, b.forbiddenHeaderParams)),
	}
}
