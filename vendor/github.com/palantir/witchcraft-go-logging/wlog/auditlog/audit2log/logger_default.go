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

package audit2log

import (
	"time"

	"github.com/palantir/witchcraft-go-logging/wlog"
)

type defaultLogger struct {
	logger wlog.Logger
}

func (l *defaultLogger) Audit(name string, result AuditResultType, params ...Param) {
	l.logger.Log(ToParams(name, result, params)...)
}

func ToParams(name string, result AuditResultType, inParams []Param) []wlog.Param {
	outParams := make([]wlog.Param, len(defaultTypeParam)+1+len(inParams))
	copy(outParams, defaultTypeParam)
	outParams[len(defaultTypeParam)] = wlog.NewParam(auditNameResultParam(name, result).apply)
	for idx := range inParams {
		outParams[len(defaultTypeParam)+1+idx] = wlog.NewParam(inParams[idx].apply)
	}
	return outParams
}

var defaultTypeParam = []wlog.Param{
	wlog.NewParam(func(entry wlog.LogEntry) {
		entry.StringValue(wlog.TypeKey, TypeValue)
		entry.StringValue(wlog.TimeKey, time.Now().Format(time.RFC3339Nano))
	}),
}
