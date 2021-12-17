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
	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type wrappedSvc1Logger struct {
	name    string
	version string
	params  []svc1log.Param

	logger wlog.LeveledLogger
	level  wlog.LevelChecker
}

func (l *wrappedSvc1Logger) Debug(msg string, params ...svc1log.Param) {
	if l.enabled(wlog.DebugLevel) {
		l.logger.Debug("", l.toServiceParams(msg, svc1log.DebugLevelParam(), params)...)
	}
}

func (l *wrappedSvc1Logger) Info(msg string, params ...svc1log.Param) {
	if l.enabled(wlog.InfoLevel) {
		l.logger.Info("", l.toServiceParams(msg, svc1log.InfoLevelParam(), params)...)
	}
}

func (l *wrappedSvc1Logger) Warn(msg string, params ...svc1log.Param) {
	if l.enabled(wlog.WarnLevel) {
		l.logger.Warn("", l.toServiceParams(msg, svc1log.WarnLevelParam(), params)...)
	}
}

func (l *wrappedSvc1Logger) Error(msg string, params ...svc1log.Param) {
	if l.enabled(wlog.ErrorLevel) {
		l.logger.Error("", l.toServiceParams(msg, svc1log.ErrorLevelParam(), params)...)
	}
}

func (l *wrappedSvc1Logger) SetLevel(level wlog.LogLevel) {
	l.logger.SetLevel(level)
}

func (l *wrappedSvc1Logger) enabled(level wlog.LogLevel) bool {
	return l.level == nil || l.level.Enabled(level)
}

func (l *wrappedSvc1Logger) toServiceParams(message string, levelParam wlog.Param, inParams []svc1log.Param) []wlog.Param {
	outParams := make([]wlog.Param, len(defaultTypeParam)+2)
	copy(outParams, defaultTypeParam)
	outParams[len(defaultTypeParam)] = wlog.NewParam(wrappedTypeParams(l.name, l.version).apply)
	outParams[len(defaultTypeParam)+1] = wlog.NewParam(svc1PayloadParams(message, levelParam, append(l.params, inParams...)).apply)
	return outParams
}
