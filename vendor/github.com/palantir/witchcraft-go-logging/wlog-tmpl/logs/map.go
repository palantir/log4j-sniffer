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
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

var Unwrappers = map[logentryformatter.LogType]logentryformatter.Unwrapper{
	"wrapped.1": wrapped1Unwrapper,
}

var formatters = []logTyper{
	svc1LogType,
	req2LogType,
	evt1LogType,
	evt2LogType,
	metric1LogType,
	trace1LogType,
	req1LogType,
	diagnostics1LogType,
}

func OrderedLogTypes() []logentryformatter.LogType {
	types := make([]logentryformatter.LogType, len(formatters))
	for i, v := range formatters {
		types[i] = v.LogType()
	}
	return types
}

func Formatters(params ...logentryformatter.Param) map[logentryformatter.LogType]logentryformatter.Formatter {
	fmtrs := make(map[logentryformatter.LogType]logentryformatter.Formatter)
	for _, v := range formatters {
		fmtrs[v.LogType()] = v.DefaultFormatter(params...)
	}
	return fmtrs
}

func Formatter(typ logentryformatter.LogType, tmpl string, params ...logentryformatter.Param) (logentryformatter.Formatter, error) {
	for _, fmtr := range formatters {
		if fmtr.LogType() == typ {
			return fmtr.NewFormatter(tmpl, params...)
		}
	}
	return logentryformatter.New(func(lineJSON []byte, substitute bool) (interface{}, error) {
		// unmarshal as generic JSON map
		var m map[string]interface{}
		err := safejson.Unmarshal(lineJSON, &m)
		return m, err
	}, tmpl)
}
