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
	"github.com/palantir/witchcraft-go-logging/wlog"
)

type wrappedLogger struct {
	logger Logger
	params []Param
}

func (w *wrappedLogger) Debug(msg string, params ...Param) {
	w.logger.Debug(msg, append(w.params, params...)...)
}

func (w *wrappedLogger) Info(msg string, params ...Param) {
	w.logger.Info(msg, append(w.params, params...)...)
}

func (w *wrappedLogger) Warn(msg string, params ...Param) {
	w.logger.Warn(msg, append(w.params, params...)...)
}

func (w *wrappedLogger) Error(msg string, params ...Param) {
	w.logger.Error(msg, append(w.params, params...)...)
}

func (w *wrappedLogger) SetLevel(level wlog.LogLevel) {
	w.logger.SetLevel(level)
}
