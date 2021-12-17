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

package trc1log

import (
	"github.com/palantir/witchcraft-go-logging/wlog"
)

const (
	TypeValue = "trace.1"

	SpanKey = "span"

	SpanIDKey          = "id"
	SpanNameKey        = "name"
	SpanParentIDKey    = "parentId"
	SpanTimestampKey   = "timestamp"
	SpanDurationKey    = "duration"
	SpanAnnotationsKey = "annotations"
	SpanTagsKey        = "tags"

	AnnotationTimestampKey = "timestamp"
	AnnotationValueKey     = "value"
	AnnotationEndpointKey  = "endpoint"

	EndpointServiceNameKey = "serviceName"
	EndpointIPv4Key        = "ipv4"
	EndpointIPv6Key        = "ipv6"
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

func UnsafeParam(key string, value interface{}) Param {
	return UnsafeParams(map[string]interface{}{
		key: value,
	})
}

func UnsafeParams(unsafe map[string]interface{}) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.AnyMapValue(wlog.UnsafeParamsKey, unsafe)
	})
}
