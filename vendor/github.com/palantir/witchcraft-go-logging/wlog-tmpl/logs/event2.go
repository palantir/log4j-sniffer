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
	"github.com/palantir/pkg/safejson"
	"github.com/palantir/witchcraft-go-logging/conjure/witchcraft/api/logging"
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

var evt2LogType = &evt2LogTyper{
	baseLogTyper: baseLogTyper{
		typ:         "event.2",
		defaultTmpl: `{{printf "%-26s" (printf "[%s]" .Time)}} {{.EventName}}{{if .Values}} {{niceMap .Values}}{{end}}{{if .UnsafeParams}} {{niceMap .UnsafeParams}}{{end}}`,
		defaultObj:  logging.EventLogV2{},
	},
}

type evt2LogTyper struct {
	baseLogTyper
}

func (r *evt2LogTyper) DefaultFormatter(params ...logentryformatter.Param) logentryformatter.Formatter {
	return r.baseLogTyper.defaultFormatter(r, params...)
}

func (r *evt2LogTyper) NewFormatter(tmpl string, params ...logentryformatter.Param) (logentryformatter.Formatter, error) {
	newParams := append(r.baseLogTyper.baseParams(), params...)
	return logentryformatter.New(r.parseLogEntry, tmpl, newParams...)
}

func (r *evt2LogTyper) parseLogEntry(lineJSON []byte, substitute bool) (interface{}, error) {
	var res logging.EventLogV2
	if err := safejson.Unmarshal(lineJSON, &res); err != nil {
		return nil, err
	}
	return res, nil
}
