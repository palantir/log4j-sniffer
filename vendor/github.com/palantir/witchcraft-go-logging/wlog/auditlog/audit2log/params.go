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
	"github.com/palantir/witchcraft-go-logging/wlog"
)

const (
	TypeValue = "audit.2"

	OtherUIDsKey     = "otherUids"
	OriginKey        = "origin"
	NameKey          = "name"
	ResultKey        = "result"
	RequestParamsKey = "requestParams"
	ResultParamsKey  = "resultParams"
)

type Param interface {
	apply(entry wlog.LogEntry)
}

func ApplyParam(p Param, entry wlog.LogEntry) {
	if p == nil {
		return
	}
	p.apply(entry)
}

type paramFunc func(entry wlog.LogEntry)

func (f paramFunc) apply(entry wlog.LogEntry) {
	f(entry)
}

func auditNameResultParam(name string, resultType AuditResultType) Param {
	return paramFunc(func(logger wlog.LogEntry) {
		logger.StringValue(NameKey, name)
		logger.StringValue(ResultKey, string(resultType))
	})
}

func UID(uid string) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.OptionalStringValue(wlog.UIDKey, uid)
	})
}

func SID(sid string) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.OptionalStringValue(wlog.SIDKey, sid)
	})
}

func TokenID(tokenID string) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.OptionalStringValue(wlog.TokenIDKey, tokenID)
	})
}

func TraceID(traceID string) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.OptionalStringValue(wlog.TraceIDKey, traceID)
	})
}

func OtherUIDs(otherUIDs ...string) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.StringListValue(OtherUIDsKey, otherUIDs)
	})
}

func Origin(origin string) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.OptionalStringValue(OriginKey, origin)
	})
}

func RequestParam(key string, value interface{}) Param {
	return RequestParams(map[string]interface{}{
		key: value,
	})
}

func RequestParams(requestParams map[string]interface{}) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.AnyMapValue(RequestParamsKey, requestParams)
	})
}

func ResultParam(key string, value interface{}) Param {
	return ResultParams(map[string]interface{}{
		key: value,
	})
}

func ResultParams(resultParams map[string]interface{}) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.AnyMapValue(ResultParamsKey, resultParams)
	})
}
