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

package wlog

import (
	"io"
	"reflect"
)

type LogEntry interface {
	StringValue(k, v string)
	OptionalStringValue(k, v string)
	SafeLongValue(k string, v int64)
	IntValue(k string, v int32)
	StringListValue(k string, v []string)
	StringMapValue(k string, v map[string]string)
	AnyMapValue(k string, v map[string]interface{})

	// ObjectValue logs the provided value associated with the specified key. If marshalerType is non-nil, then if a
	// custom marshaler is registered for that type, it may be used to log the entry. If marshalerType is nil or no
	// marshaler is registered for the provided type, the entry should be logged using reflection.
	ObjectValue(k string, v interface{}, marshalerType reflect.Type)
}

type Logger interface {
	Log(params ...Param)
}

type LoggerCreator func(w io.Writer) Logger

type LeveledLoggerCreator func(w io.Writer, level LogLevel) LeveledLogger

type LeveledLogger interface {
	Debug(msg string, params ...Param)
	Info(msg string, params ...Param)
	Warn(msg string, params ...Param)
	Error(msg string, params ...Param)
	SetLevel(level LogLevel)
}

type LevelChecker interface {
	// Enabled determines whether the provided level should be logged.
	// If implemented with LeveledLogger or SetLevel, they must remain consistent with Enabled.
	Enabled(level LogLevel) bool
}

type MapValueEntries struct {
	stringMapValues map[string]map[string]string
	anyMapValues    map[string]map[string]interface{}
}

func (m *MapValueEntries) StringMapValue(key string, values map[string]string) {
	if len(values) == 0 {
		return
	}
	if m.stringMapValues == nil {
		m.stringMapValues = make(map[string]map[string]string)
	}
	entryMapVals, ok := m.stringMapValues[key]
	if !ok {
		entryMapVals = make(map[string]string)
		m.stringMapValues[key] = entryMapVals
	}
	for k, v := range values {
		entryMapVals[k] = v
	}
}

func (m *MapValueEntries) AnyMapValue(key string, values map[string]interface{}) {
	if len(values) == 0 {
		return
	}
	if len(values) == 0 {
		return
	}
	if m.anyMapValues == nil {
		m.anyMapValues = make(map[string]map[string]interface{})
	}
	entryMapVals, ok := m.anyMapValues[key]
	if !ok {
		entryMapVals = make(map[string]interface{})
		m.anyMapValues[key] = entryMapVals
	}
	for k, v := range values {
		entryMapVals[k] = v
	}
}

func (m *MapValueEntries) StringMapValues() map[string]map[string]string {
	return m.stringMapValues
}

func (m *MapValueEntries) AnyMapValues() map[string]map[string]interface{} {
	return m.anyMapValues
}
