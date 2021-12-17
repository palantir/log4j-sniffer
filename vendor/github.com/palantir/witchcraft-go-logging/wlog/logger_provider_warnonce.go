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
	"fmt"
	"io"
	"sync"
)

func newWarnOnceLoggerProvider() LoggerProvider {
	return &warnOnceLoggerProvider{}
}

type warnOnceLogger struct {
	w    io.Writer
	once sync.Once
}

func (l *warnOnceLogger) Log(params ...Param)               { l.once.Do(l.printWarning) }
func (l *warnOnceLogger) Debug(msg string, params ...Param) { l.once.Do(l.printWarning) }
func (l *warnOnceLogger) Info(msg string, params ...Param)  { l.once.Do(l.printWarning) }
func (l *warnOnceLogger) Warn(msg string, params ...Param)  { l.once.Do(l.printWarning) }
func (l *warnOnceLogger) Error(msg string, params ...Param) { l.once.Do(l.printWarning) }
func (l *warnOnceLogger) SetLevel(level LogLevel)           { l.once.Do(l.printWarning) }

func (l *warnOnceLogger) printWarning() {
	_, _ = fmt.Fprintln(l.w, `[WARNING] Logging operation that uses the default logger provider was performed without specifying a logger provider implementation. `+
		`To see logger output, set the global logger provider implementation using wlog.SetDefaultLoggerProvider or by importing an implementation. `+
		`This warning can be disabled by setting the global logger provider to be the noop logger provider using wlog.SetDefaultLoggerProvider(wlog.NewNoopLoggerProvider()).`)
}

type warnOnceLoggerProvider struct{}

func (*warnOnceLoggerProvider) NewLogger(w io.Writer) Logger {
	return &warnOnceLogger{
		w: w,
	}
}

func (*warnOnceLoggerProvider) NewLeveledLogger(w io.Writer, level LogLevel) LeveledLogger {
	return &warnOnceLogger{
		w: w,
	}
}

func (*warnOnceLoggerProvider) NewLogEntry() LogEntry {
	return &noopLogEntry{}
}
