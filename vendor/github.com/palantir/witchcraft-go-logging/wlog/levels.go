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
	"strings"
	"sync/atomic"
)

type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
	FatalLevel LogLevel = "fatal"
)

func (l *LogLevel) UnmarshalText(b []byte) error {
	switch strings.ToLower(string(b)) {
	case string(DebugLevel):
		*l = DebugLevel
		return nil
	case "", string(InfoLevel):
		*l = InfoLevel
		return nil
	case string(WarnLevel):
		*l = WarnLevel
		return nil
	case string(ErrorLevel):
		*l = ErrorLevel
		return nil
	case string(FatalLevel):
		*l = FatalLevel
		return nil
	default:
		return fmt.Errorf("invalid log level: %q", string(b))
	}
}

func (l LogLevel) Enabled(other LogLevel) bool {
	switch l {
	case DebugLevel:
		switch other {
		case DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel:
			return true
		}
	case InfoLevel:
		switch other {
		case InfoLevel, WarnLevel, ErrorLevel, FatalLevel:
			return true
		}
	case WarnLevel:
		switch other {
		case WarnLevel, ErrorLevel, FatalLevel:
			return true
		}
	case ErrorLevel:
		switch other {
		case ErrorLevel, FatalLevel:
			return true
		}
	case FatalLevel:
		switch other {
		case FatalLevel:
			return true
		}
	}
	return false
}

// AtomicLogLevel wraps atomic.Value containing a LogLevel.
// Always use NewAtomicLogLevel to create it.
type AtomicLogLevel struct {
	value atomic.Value
	noCopy
}

func NewAtomicLogLevel(level LogLevel) *AtomicLogLevel {
	a := &AtomicLogLevel{}
	a.SetLevel(level)
	return a
}

func (l *AtomicLogLevel) LogLevel() LogLevel {
	return l.value.Load().(LogLevel)
}

func (l *AtomicLogLevel) SetLevel(level LogLevel) {
	l.value.Store(level)
}

func (l *AtomicLogLevel) Enabled(other LogLevel) bool {
	return l.LogLevel().Enabled(other)
}

// noCopy may be embedded into structs which must not be copied
// after the first use.
//
// See https://golang.org/issues/8005#issuecomment-190753527
// for details.
// Copied from the standard library's sync package.
type noCopy struct{}

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
