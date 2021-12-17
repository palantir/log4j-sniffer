// Copyright (c) 2021 Palantir Technologies. All rights reserved.
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

package wrapped1log

import (
	"io"

	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog/extractor"
	"github.com/palantir/witchcraft-go-logging/wlog/reqlog/req2log"
)

type wrappedReq2Logger struct {
	name             string
	version          string
	idsExtractor     extractor.IDsFromRequest
	pathParamPerms   req2log.ParamPerms
	queryParamPerms  req2log.ParamPerms
	headerParamPerms req2log.ParamPerms

	logger wlog.Logger
}

func (l *wrappedReq2Logger) Request(r req2log.Request) {
	l.logger.Log(l.toRequestParams(r)...)
}

func (l *wrappedReq2Logger) PathParamPerms() req2log.ParamPerms {
	return l.pathParamPerms
}

func (l *wrappedReq2Logger) QueryParamPerms() req2log.ParamPerms {
	return l.queryParamPerms
}

func (l *wrappedReq2Logger) HeaderParamPerms() req2log.ParamPerms {
	return l.headerParamPerms
}

func (l *wrappedReq2Logger) toRequestParams(r req2log.Request) []wlog.Param {
	outParams := make([]wlog.Param, len(defaultTypeParam)+2)
	copy(outParams, defaultTypeParam)
	outParams[len(defaultTypeParam)] = wlog.NewParam(wrappedTypeParams(l.name, l.version).apply)
	outParams[len(defaultTypeParam)+1] = wlog.NewParam(req2PayloadParams(r, l.idsExtractor, l.pathParamPerms, l.queryParamPerms, l.headerParamPerms).apply)
	return outParams
}

type req2LoggerBuilder struct {
	name    string
	version string

	loggerCreator wlog.LoggerCreator
	idsExtractor  extractor.IDsFromRequest

	safePathParams      []string
	forbiddenPathParams []string

	safeQueryParams      []string
	forbiddenQueryParams []string

	safeHeaderParams      []string
	forbiddenHeaderParams []string
}

func (b *req2LoggerBuilder) LoggerCreator(creator wlog.LoggerCreator) {
	b.loggerCreator = creator
}

func (b *req2LoggerBuilder) IdsExtractor(idsExtractor extractor.IDsFromRequest) {
	b.idsExtractor = idsExtractor
}

func (b *req2LoggerBuilder) SafePathParams(safePathParams []string) {
	b.safePathParams = append(b.safePathParams, safePathParams...)
}

func (b *req2LoggerBuilder) ForbiddenPathParams(forbiddenPathParams []string) {
	b.forbiddenPathParams = append(b.forbiddenPathParams, forbiddenPathParams...)
}

func (b *req2LoggerBuilder) SafeQueryParams(safeQueryParams []string) {
	b.safeQueryParams = append(b.safeQueryParams, safeQueryParams...)
}

func (b *req2LoggerBuilder) ForbiddenQueryParams(forbiddenQueryParams []string) {
	b.forbiddenQueryParams = append(b.forbiddenQueryParams, forbiddenQueryParams...)
}

func (b *req2LoggerBuilder) SafeHeaderParams(safeHeaderParams []string) {
	b.safeHeaderParams = append(b.safeHeaderParams, safeHeaderParams...)
}

func (b *req2LoggerBuilder) ForbiddenHeaderParams(forbiddenHeaderParams []string) {
	b.forbiddenHeaderParams = append(b.forbiddenHeaderParams, forbiddenHeaderParams...)
}

func (b *req2LoggerBuilder) build(w io.Writer) *wrappedReq2Logger {
	defaultParams := req2log.DefaultRequestParamPerms()
	return &wrappedReq2Logger{
		name:             b.name,
		version:          b.version,
		idsExtractor:     b.idsExtractor,
		pathParamPerms:   req2log.CombinedParamPerms(defaultParams.PathParamPerms(), req2log.NewParamPerms(b.safePathParams, b.forbiddenPathParams)),
		queryParamPerms:  req2log.CombinedParamPerms(defaultParams.QueryParamPerms(), req2log.NewParamPerms(b.safeQueryParams, b.forbiddenQueryParams)),
		headerParamPerms: req2log.CombinedParamPerms(defaultParams.HeaderParamPerms(), req2log.NewParamPerms(b.safeHeaderParams, b.forbiddenHeaderParams)),

		logger: b.loggerCreator(w),
	}
}
