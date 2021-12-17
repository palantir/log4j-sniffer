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

package svc1log

import (
	"io"

	"github.com/palantir/witchcraft-go-logging/wlog"
)

type Logger interface {
	Debug(msg string, params ...Param)
	Info(msg string, params ...Param)
	Warn(msg string, params ...Param)
	Error(msg string, params ...Param)
	SetLevel(level wlog.LogLevel)
}

func New(w io.Writer, level wlog.LogLevel, params ...Param) Logger {
	return NewFromCreator(w, level, wlog.DefaultLoggerProvider().NewLeveledLogger, params...)
}

func NewFromCreator(w io.Writer, level wlog.LogLevel, creator wlog.LeveledLoggerCreator, params ...Param) Logger {
	delegate := creator(w, level)
	// The second return value is ignored because 'level: nil' is a valid state handled in the implementation.
	levelChecker, _ := delegate.(wlog.LevelChecker)
	return WithParams(&defaultLogger{
		logger: delegate,
		level:  levelChecker,
	}, params...)
}

func WithParams(logger Logger, params ...Param) Logger {
	// Note that wrapping is performed even if len(params) == 0. This is done intentionally to ensure that every default
	// logger evaluates its parameters at the same level in the stack, which is required to ensure that the
	// OriginFromCallLine parameter works generically.

	if innerWrapped, ok := logger.(*wrappedLogger); ok {
		return &wrappedLogger{
			logger: innerWrapped.logger,
			params: append(innerWrapped.params, params...),
		}
	}

	return &wrappedLogger{
		logger: logger,
		params: params,
	}
}
