// Copyright (c) 2020 Palantir Technologies. All rights reserved.
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

package wlogtmpl

import (
	"fmt"
	"io"
	"time"

	"github.com/palantir/pkg/bytesbuffers"
	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

type tmplLogger struct {
	w   io.Writer
	cfg *Config
	*wlog.AtomicLogLevel

	delegate   wlog.LoggerCreator
	bufferPool bytesbuffers.Pool
}

func (l *tmplLogger) Log(params ...wlog.Param) {
	l.logOutput(params)
}

func (l *tmplLogger) Debug(msg string, params ...wlog.Param) {
	if l.Enabled(wlog.DebugLevel) {
		l.logOutput(append(params, wlog.StringParam("message", msg), wlog.StringParam("level", "DEBUG")))
	}
}

func (l *tmplLogger) Info(msg string, params ...wlog.Param) {
	if l.Enabled(wlog.InfoLevel) {
		l.logOutput(append(params, wlog.StringParam("message", msg), wlog.StringParam("level", "INFO")))
	}
}

func (l *tmplLogger) Warn(msg string, params ...wlog.Param) {
	if l.Enabled(wlog.WarnLevel) {
		l.logOutput(append(params, wlog.StringParam("message", msg), wlog.StringParam("level", "WARN")))
	}
}

func (l *tmplLogger) Error(msg string, params ...wlog.Param) {
	if l.Enabled(wlog.ErrorLevel) {
		l.logOutput(append(params, wlog.StringParam("message", msg), wlog.StringParam("level", "ERROR")))
	}
}

func (l *tmplLogger) logOutput(params []wlog.Param) {
	_, _ = fmt.Fprintln(l.w, l.formatOutput(params))
}

func (l *tmplLogger) formatOutput(params []wlog.Param) string {
	params = append(params, wlog.StringParam(wlog.TimeKey, time.Now().Format(time.RFC3339Nano)))

	buf := l.bufferPool.Get()
	defer l.bufferPool.Put(buf)
	l.delegate(buf).Log(params...)

	out, err := logentryformatter.FormatLogLine(buf.String(), l.cfg.UnwrapperMap, l.cfg.FormatterMap, l.cfg.Only, l.cfg.Exclude)
	if err != nil {
		if !l.cfg.Strict {
			return buf.String()
		}
		return err.Error()
	}
	return out
}
