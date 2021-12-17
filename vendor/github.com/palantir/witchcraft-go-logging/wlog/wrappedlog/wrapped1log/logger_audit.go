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
	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog/auditlog/audit2log"
)

type wrappedAudit2Logger struct {
	name    string
	version string

	logger wlog.Logger
}

func (l *wrappedAudit2Logger) Audit(name string, result audit2log.AuditResultType, params ...audit2log.Param) {
	l.logger.Log(l.toAuditParams(name, result, params)...)
}

func (l *wrappedAudit2Logger) toAuditParams(name string, result audit2log.AuditResultType, params []audit2log.Param) []wlog.Param {
	outParams := make([]wlog.Param, len(defaultTypeParam)+2)
	copy(outParams, defaultTypeParam)
	outParams[len(defaultTypeParam)] = wlog.NewParam(wrappedTypeParams(l.name, l.version).apply)
	outParams[len(defaultTypeParam)+1] = wlog.NewParam(audit2PayloadParams(name, result, params).apply)
	return outParams
}
