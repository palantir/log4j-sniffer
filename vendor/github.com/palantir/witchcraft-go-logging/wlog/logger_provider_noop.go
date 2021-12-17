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

// NewNoopLoggerProvider returns a LoggerProvider whose implementations
// are no-ops. That is, they return immediately after doing nothing.
func NewNoopLoggerProvider() LoggerProvider {
	return &noopLoggerProvider{}
}

type nooplogger struct{}

func (*nooplogger) Log(params ...Param)               {}
func (*nooplogger) Debug(msg string, params ...Param) {}
func (*nooplogger) Info(msg string, params ...Param)  {}
func (*nooplogger) Warn(msg string, params ...Param)  {}
func (*nooplogger) Error(msg string, params ...Param) {}
func (*nooplogger) SetLevel(level LogLevel)           {}

type noopLoggerProvider struct{}

func (*noopLoggerProvider) NewLogger(w io.Writer) Logger {
	return &nooplogger{}
}

func (*noopLoggerProvider) NewLeveledLogger(w io.Writer, level LogLevel) LeveledLogger {
	return &nooplogger{}
}

func (p *noopLoggerProvider) NewLogEntry() LogEntry {
	return &noopLogEntry{}
}

type noopLogEntry struct{}

func (*noopLogEntry) StringValue(k, v string)                                         {}
func (*noopLogEntry) OptionalStringValue(k, v string)                                 {}
func (*noopLogEntry) StringListValue(k string, v []string)                            {}
func (*noopLogEntry) SafeLongValue(k string, v int64)                                 {}
func (*noopLogEntry) IntValue(k string, v int32)                                      {}
func (*noopLogEntry) StringMapValue(k string, v map[string]string)                    {}
func (*noopLogEntry) AnyMapValue(k string, v map[string]interface{})                  {}
func (*noopLogEntry) ObjectValue(k string, v interface{}, marshalerType reflect.Type) {}
