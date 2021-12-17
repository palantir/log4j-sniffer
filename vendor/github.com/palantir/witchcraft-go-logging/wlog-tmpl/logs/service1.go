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

package logs

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/fatih/color"
	"github.com/palantir/pkg/safejson"
	"github.com/palantir/witchcraft-go-logging/conjure/witchcraft/api/logging"
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

var svc1LogType = &svc1LogTyper{
	baseLogTyper: baseLogTyper{
		typ:         "service.1",
		defaultTmpl: `{{printf "%-5s" .Level}} {{printf "%-26s" (printf "[%s]" .Time)}}{{if .Origin}} {{.Origin}}:{{end}} {{.Message}}{{if .Params}} {{niceMap .Params}}{{end}}{{if .UnsafeParams}} {{niceMap .UnsafeParams}}{{end}}{{if .Stacktrace}}{{println}}{{.Stacktrace}}{{end}}`,
		defaultObj:  logging.ServiceLogV1{},
	},
}

type svc1LogTyper struct {
	baseLogTyper
}

func (r *svc1LogTyper) DefaultFormatter(params ...logentryformatter.Param) logentryformatter.Formatter {
	return r.baseLogTyper.defaultFormatter(r, params...)
}

func (r *svc1LogTyper) NewFormatter(tmpl string, params ...logentryformatter.Param) (logentryformatter.Formatter, error) {
	newParams := append(r.baseLogTyper.baseParams(), logentryformatter.Colorizer(ServiceLogLevelColorer))
	newParams = append(newParams, params...)
	return logentryformatter.New(r.parseLogEntry, tmpl, newParams...)
}

func (r *svc1LogTyper) parseLogEntry(lineJSON []byte, substitute bool) (interface{}, error) {
	var res logging.ServiceLogV1
	if err := safejson.Unmarshal(lineJSON, &res); err != nil {
		return nil, err
	}
	if substitute {
		performRenderSubstitution(&res)
	}
	return res, nil
}

var blankPlaceholderRegex = regexp.MustCompile(`{}`)

var namedPlaceholderRegex = regexp.MustCompile(`{[^{}]+}`)

func performRenderSubstitution(logEntry *logging.ServiceLogV1) {
	blankIdx := 0
	logEntry.Message = blankPlaceholderRegex.ReplaceAllStringFunc(logEntry.Message, func(match string) string {
		rv := match
		if unsafeVal, ok := logEntry.UnsafeParams[strconv.Itoa(blankIdx)]; ok {
			rv = fmt.Sprint(unsafeVal)
		}
		blankIdx++
		return rv
	})
	if logEntry.Stacktrace != nil {
		substitutedTrace := namedPlaceholderRegex.ReplaceAllStringFunc(*logEntry.Stacktrace, func(match string) string {
			k := match[1 : len(match)-1]
			if safeVal, ok := logEntry.Params[k]; ok {
				return fmt.Sprint(safeVal)
			}
			if unsafeVal, ok := logEntry.UnsafeParams[k]; ok {
				return fmt.Sprint(unsafeVal)
			}
			return match
		})
		logEntry.Stacktrace = &substitutedTrace
	}
}

var (
	logLevelColors = map[logging.LogLevel_Value]*color.Color{
		logging.LogLevel_WARN:  color.New(color.FgYellow),
		logging.LogLevel_ERROR: color.New(color.FgRed),
	}
)

func ServiceLogLevelColorer(in interface{}) *color.Color {
	sle, ok := in.(logging.ServiceLogV1)
	if !ok {
		return nil
	}
	return logLevelColors[sle.Level.Value()]
}
