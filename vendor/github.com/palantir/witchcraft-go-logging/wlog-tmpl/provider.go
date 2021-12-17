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
	"io"

	"github.com/palantir/pkg/bytesbuffers"
	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logs"
)

type tmplLoggerProvider struct {
	cfg *Config
}

type Config struct {
	// Strict mode emits formatting errors as log lines; by default, the raw output will be printed if it can't be formatted.
	Strict        bool
	UnwrapperMap  map[logentryformatter.LogType]logentryformatter.Unwrapper
	FormatterMap  map[logentryformatter.LogType]logentryformatter.Formatter
	Only, Exclude map[logentryformatter.LogType]struct{}
	// DelegateLogger is used to create the intermediate json representation that is passed to the template.
	DelegateLogger wlog.LoggerProvider
}

// LoggerProvider returns a wlog.LoggerProvider which formats log entries with wlog templates.
// The default templates give a human-friendly output suitable for command-line tools.
// Services which leverage log collection infrastructure should use a JSON-based provider.
//
// Nil configuration is valid and will result in the default behavior.
func LoggerProvider(cfg *Config, params ...logentryformatter.Param) wlog.LoggerProvider {
	if cfg == nil {
		cfg = &Config{}
	}
	if len(cfg.UnwrapperMap) == 0 {
		cfg.UnwrapperMap = logs.Unwrappers
	}
	defaultFormatterMap := logs.Formatters(params...)
	if len(cfg.FormatterMap) == 0 {
		cfg.FormatterMap = defaultFormatterMap
	} else {
		// Add default impls for types not set in cfg
		for k := range defaultFormatterMap {
			if _, exists := cfg.FormatterMap[k]; !exists {
				cfg.FormatterMap[k] = defaultFormatterMap[k]
			}
		}
	}
	if cfg.DelegateLogger == nil {
		cfg.DelegateLogger = wlog.NewJSONMarshalLoggerProvider()
	}
	return &tmplLoggerProvider{
		cfg: cfg,
	}
}

func (p *tmplLoggerProvider) NewLogger(w io.Writer) wlog.Logger {
	return &tmplLogger{
		w:          w,
		cfg:        p.cfg,
		delegate:   p.cfg.DelegateLogger.NewLogger,
		bufferPool: bytesbuffers.NewSyncPool(128),
	}
}

func (p *tmplLoggerProvider) NewLeveledLogger(w io.Writer, level wlog.LogLevel) wlog.LeveledLogger {
	return &tmplLogger{
		w:              w,
		cfg:            p.cfg,
		AtomicLogLevel: wlog.NewAtomicLogLevel(level),
		delegate:       p.cfg.DelegateLogger.NewLogger,
		bufferPool:     bytesbuffers.NewSyncPool(128),
	}
}
