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
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// NewJSONMarshalLoggerProvider returns a new logger provider that uses a MapLogEntry as its log entry and performs
// logging by performing a json.Marshal of the MapLogEntry. This is a naive implementation that is not very efficient:
// its primary purpose is for tests and in-memory usage in scenarios where one does not want to use a logger provider
// that uses an external library.
func NewJSONMarshalLoggerProvider() LoggerProvider {
	return &jsonMarshalLoggerProvider{}
}

type jsonMapLogger struct {
	w io.Writer
	*AtomicLogLevel
}

func (l *jsonMapLogger) Log(params ...Param) {
	l.logOutput(params)
}

func (l *jsonMapLogger) Debug(msg string, params ...Param) {
	if l.Enabled(DebugLevel) {
		l.logOutput(ParamsWithMessage(msg, params))
	}
}

func (l *jsonMapLogger) Info(msg string, params ...Param) {
	if l.Enabled(InfoLevel) {
		l.logOutput(ParamsWithMessage(msg, params))
	}
}

func (l *jsonMapLogger) Warn(msg string, params ...Param) {
	if l.Enabled(WarnLevel) {
		l.logOutput(ParamsWithMessage(msg, params))
	}
}

func (l *jsonMapLogger) Error(msg string, params ...Param) {
	if l.Enabled(ErrorLevel) {
		l.logOutput(ParamsWithMessage(msg, params))
	}
}

func (l *jsonMapLogger) logOutput(params []Param) {
	params = append(params, StringParam(TimeKey, time.Now().Format(time.RFC3339Nano)))

	entry := NewMapLogEntry()
	ApplyParams(entry, params)
	bytes, _ := json.Marshal(entry.AllValues())
	_, _ = fmt.Fprintln(l.w, string(bytes))
}

type jsonMarshalLoggerProvider struct{}

func (*jsonMarshalLoggerProvider) NewLogger(w io.Writer) Logger {
	return &jsonMapLogger{
		w: w,
	}
}

func (*jsonMarshalLoggerProvider) NewLeveledLogger(w io.Writer, level LogLevel) LeveledLogger {
	return &jsonMapLogger{
		w:              w,
		AtomicLogLevel: NewAtomicLogLevel(level),
	}
}

func (p *jsonMarshalLoggerProvider) NewLogEntry() LogEntry {
	return NewMapLogEntry()
}
