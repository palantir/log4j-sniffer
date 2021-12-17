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

	"github.com/palantir/pkg/safejson"
	"github.com/palantir/witchcraft-go-logging/conjure/witchcraft/api/logging"
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

var req1LogType = &req1LogTyper{
	baseLogTyper: baseLogTyper{
		typ:         "request.1",
		defaultTmpl: `{{with $time := .Time | printf "[%s]"}}{{if le (len $time) 26 }}{{printf "%-26s" $time}}{{else}}{{printf "%-32s" $time}}{{end}}{{end}} "{{if .Method}}{{.Method}} {{end}}{{.Path}} {{.Protocol}}" {{.Status}} {{.ResponseSize}} {{.Duration}}`,
		defaultObj:  logging.RequestLogV1{},
	},
}

type req1LogTyper struct {
	baseLogTyper
}

func (r *req1LogTyper) DefaultFormatter(params ...logentryformatter.Param) logentryformatter.Formatter {
	return r.baseLogTyper.defaultFormatter(r, params...)
}

func (r *req1LogTyper) NewFormatter(tmpl string, params ...logentryformatter.Param) (logentryformatter.Formatter, error) {
	newParams := append(r.baseLogTyper.baseParams(), params...)

	return logentryformatter.New(r.parseLogEntry, tmpl, newParams...)
}

func (r *req1LogTyper) parseLogEntry(lineJSON []byte, substitute bool) (interface{}, error) {
	var res logging.RequestLogV1
	if err := safejson.Unmarshal(lineJSON, &res); err != nil {
		return nil, err
	}
	if substitute {
		performRequest1PathParamSubstitution(&res)
	}
	return res, nil
}

var requestParamRegexp = regexp.MustCompile(`{[^{}]+}`)
var colonOrAsterix = regexp.MustCompile(`:|\*`)

func performRequest1PathParamSubstitution(logEntry *logging.RequestLogV1) {
	logEntry.Path = requestParamRegexp.ReplaceAllStringFunc(logEntry.Path, func(match string) string {
		rv := match

		varName := rv[1 : len(rv)-1]
		if loc := colonOrAsterix.FindStringIndex(varName); loc != nil {
			varName = varName[:loc[0]]
		}

		if val, ok := logEntry.PathParams[varName]; ok {
			rv = fmt.Sprint(val)
		} else if val, ok := logEntry.UnsafeParams[varName]; ok {
			rv = fmt.Sprint(val)
		}
		return rv
	})
}
