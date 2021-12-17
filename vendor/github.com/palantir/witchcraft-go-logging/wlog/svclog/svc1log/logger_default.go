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
	"time"

	"github.com/palantir/witchcraft-go-logging/wlog"
)

var (
	// Level params declared as variables so that they are only allocated once
	debugLevelParam = wlog.NewParam(func(entry wlog.LogEntry) {
		entry.StringValue(LevelKey, LevelDebugValue)
	})
	infoLevelParam = wlog.NewParam(func(entry wlog.LogEntry) {
		entry.StringValue(LevelKey, LevelInfoValue)
	})
	warnLevelParam = wlog.NewParam(func(entry wlog.LogEntry) {
		entry.StringValue(LevelKey, LevelWarnValue)
	})
	errorLevelParam = wlog.NewParam(func(entry wlog.LogEntry) {
		entry.StringValue(LevelKey, LevelErrorValue)
	})
)

func DebugLevelParam() wlog.Param {
	return debugLevelParam
}
func InfoLevelParam() wlog.Param {
	return infoLevelParam
}
func WarnLevelParam() wlog.Param {
	return warnLevelParam
}
func ErrorLevelParam() wlog.Param {
	return errorLevelParam
}

type defaultLogger struct {
	logger wlog.LeveledLogger
	level  wlog.LevelChecker
	params []Param
}

func (l *defaultLogger) Debug(msg string, params ...Param) {
	if l.enabled(wlog.DebugLevel) {
		l.logger.Debug(msg, ToParams(DebugLevelParam(), params)...)
	}
}

func (l *defaultLogger) Info(msg string, params ...Param) {
	if l.enabled(wlog.InfoLevel) {
		l.logger.Info(msg, ToParams(InfoLevelParam(), params)...)
	}
}

func (l *defaultLogger) Warn(msg string, params ...Param) {
	if l.enabled(wlog.WarnLevel) {
		l.logger.Warn(msg, ToParams(WarnLevelParam(), params)...)
	}
}

func (l *defaultLogger) Error(msg string, params ...Param) {
	if l.enabled(wlog.ErrorLevel) {
		l.logger.Error(msg, ToParams(ErrorLevelParam(), params)...)
	}
}

func (l *defaultLogger) SetLevel(level wlog.LogLevel) {
	l.logger.SetLevel(level)
}

func (l *defaultLogger) enabled(level wlog.LogLevel) bool {
	return l.level == nil || l.level.Enabled(level)
}

func ToParams(level wlog.Param, inParams []Param) []wlog.Param {
	outParams := make([]wlog.Param, len(defaultTypeParam)+1+len(inParams))
	copy(outParams, defaultTypeParam)
	outParams[len(defaultTypeParam)] = level
	for idx := range inParams {
		outParams[len(defaultTypeParam)+1+idx] = wlog.NewParam(inParams[idx].apply)
	}
	return outParams
}

var defaultTypeParam = []wlog.Param{
	wlog.NewParam(func(entry wlog.LogEntry) {
		entry.StringValue(wlog.TypeKey, TypeValue)
		entry.StringValue(wlog.TimeKey, time.Now().Format(time.RFC3339Nano))
	}),
}
