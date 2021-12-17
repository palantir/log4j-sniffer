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
	"io"

	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog/auditlog/audit2log"
	"github.com/palantir/witchcraft-go-logging/wlog/diaglog/diag1log"
	"github.com/palantir/witchcraft-go-logging/wlog/evtlog/evt2log"
	"github.com/palantir/witchcraft-go-logging/wlog/metriclog/metric1log"
	"github.com/palantir/witchcraft-go-logging/wlog/reqlog/req2log"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/palantir/witchcraft-go-logging/wlog/trclog/trc1log"
)

type Logger interface {
	Audit() audit2log.Logger
	Diagnostic() diag1log.Logger
	Event() evt2log.Logger
	Metric() metric1log.Logger
	Request(params ...req2log.LoggerCreatorParam) req2log.Logger
	Service(params ...svc1log.Param) svc1log.Logger
	Trace() trc1log.Logger
}

func New(w io.Writer, level wlog.LogLevel, name, version string) Logger {
	return NewFromProvider(w, level, wlog.DefaultLoggerProvider(), name, version)
}

func NewFromProvider(w io.Writer, level wlog.LogLevel, creator wlog.LoggerProvider, name, version string) Logger {
	delegate := creator.NewLeveledLogger(w, level)
	// The second return value is ignored because 'level: nil' is a valid state handled in the implementation.
	levelChecker, _ := delegate.(wlog.LevelChecker)
	return &defaultLogger{
		name:        name,
		version:     version,
		creator:     creator.NewLogger,
		writer:      w,
		logger:      creator.NewLogger(w),
		levellogger: delegate,
		level:       levelChecker,
	}
}
