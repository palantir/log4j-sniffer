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
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

type logTyper interface {
	LogType() logentryformatter.LogType
	DefaultFormatter(params ...logentryformatter.Param) logentryformatter.Formatter
	NewFormatter(tmpl string, params ...logentryformatter.Param) (logentryformatter.Formatter, error)
	parseLogEntry(lineJSON []byte, substitute bool) (interface{}, error)
}

type baseLogTyper struct {
	typ         logentryformatter.LogType
	defaultTmpl string
	defaultObj  interface{}
}

func (b *baseLogTyper) LogType() logentryformatter.LogType {
	return b.typ
}

func (b *baseLogTyper) defaultFormatter(typer logTyper, params ...logentryformatter.Param) logentryformatter.Formatter {
	fmtr, err := typer.NewFormatter(b.defaultTmpl, params...)
	if err != nil {
		panic(err)
	}
	return fmtr
}

func (b *baseLogTyper) baseParams() []logentryformatter.Param {
	return []logentryformatter.Param{
		logentryformatter.ObjDesc(logentryformatter.DescribeObject(b.defaultObj)),
	}
}
