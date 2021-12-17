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

package metric1log

import (
	"github.com/palantir/witchcraft-go-logging/wlog"
)

const (
	TypeValue = "metric.1"

	MetricNameKey = "metricName"
	MetricTypeKey = "metricType"
	ValuesKey     = "values"
	TagsKey       = "tags"
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

func metricNameTypeParam(name, typ string) Param {
	return paramFunc(func(logger wlog.LogEntry) {
		logger.StringValue(MetricNameKey, name)
		logger.StringValue(MetricTypeKey, typ)
	})
}

func Value(key string, value interface{}) Param {
	return Values(map[string]interface{}{
		key: value,
	})
}

func Values(values map[string]interface{}) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.AnyMapValue(ValuesKey, values)
	})
}

func Tag(key, value string) Param {
	return Tags(map[string]string{
		key: value,
	})
}

func Tags(values map[string]string) Param {
	return paramFunc(func(entry wlog.LogEntry) {
		entry.StringMapValue(TagsKey, values)
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
