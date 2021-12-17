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
	"sort"
	"strings"

	"github.com/palantir/pkg/datetime"
	"github.com/palantir/pkg/safejson"
	"github.com/palantir/witchcraft-go-logging/conjure/witchcraft/api/logging"
	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

var diagnostics1LogType = &diagnostics1LogTyper{
	baseLogTyper: baseLogTyper{
		typ:         "diagnostic.1",
		defaultTmpl: `{{printf "%-26s" (printf "[%s]" .Time)}}{{if .ContentOnNewLine}}{{printf "\n"}}{{else}} {{end}}{{if .UnsafeParams}}{{printf "%s\n" (niceMap .UnsafeParams)}}{{end}}{{.SerializedContent}}`,
		defaultObj:  humanReadableDiagnostic{},
	},
}

type diagnostics1LogTyper struct {
	baseLogTyper
}

func (r *diagnostics1LogTyper) DefaultFormatter(params ...logentryformatter.Param) logentryformatter.Formatter {
	return r.baseLogTyper.defaultFormatter(r, params...)
}

func (r *diagnostics1LogTyper) NewFormatter(tmpl string, params ...logentryformatter.Param) (logentryformatter.Formatter, error) {
	newParams := append(r.baseLogTyper.baseParams(), params...)
	return logentryformatter.New(r.parseLogEntry, tmpl, newParams...)
}

type humanReadableDiagnostic struct {
	SerializedContent string
	Time              datetime.DateTime
	UnsafeParams      map[string]interface{}
	Params            map[string]interface{}
	ContentOnNewLine  bool
}

func (visitor *humanReadableDiagnostic) VisitGeneric(v logging.GenericDiagnostic) error {
	visitor.SerializedContent = fmt.Sprintf("%v", v.Value)
	visitor.ContentOnNewLine = false
	return nil
}

func (visitor *humanReadableDiagnostic) VisitThreadDump(v logging.ThreadDumpV1) error {
	visitor.SerializedContent = formatThreadDumps(v, visitor.UnsafeParams)
	visitor.ContentOnNewLine = true
	return nil
}

func (visitor *humanReadableDiagnostic) VisitUnknown(typeName string) error {
	visitor.SerializedContent = fmt.Sprintf("[%s] log type is not implemented for diagnostic.1, log line will be skipped", typeName)
	visitor.ContentOnNewLine = false
	return nil
}

func (r *diagnostics1LogTyper) parseLogEntry(lineJSON []byte, substitute bool) (interface{}, error) {
	var res logging.DiagnosticLogV1
	if err := safejson.Unmarshal(lineJSON, &res); err != nil {
		return nil, err
	}
	diagnostic := humanReadableDiagnostic{UnsafeParams: res.UnsafeParams, Time: res.Time}

	if err := res.Diagnostic.Accept(&diagnostic); err != nil {
		return nil, err
	}

	return diagnostic, nil
}

func formatThreadDumps(v logging.ThreadDumpV1, unsafeParams map[string]interface{}) string {
	var sb strings.Builder
	for _, thread := range v.Threads {
		_, _ = sb.WriteString(fmt.Sprintf("%q tid=%d %s\n", extractThreadName(thread.Name, unsafeParams), *thread.Id, logentryformatter.NiceMap(thread.Params)))

		for _, trace := range thread.StackTrace {
			if trace.File != nil {
				if trace.Line != nil {
					_, _ = sb.WriteString(fmt.Sprintf("\t%s(%s:%d)\n", *trace.Procedure, *trace.File, *trace.Line))
				} else {
					_, _ = sb.WriteString(fmt.Sprintf("\t%s(%s)\n", *trace.Procedure, *trace.File))
				}
			} else {
				_, _ = sb.WriteString(fmt.Sprintf("\t%s\n", *trace.Procedure))
			}
			formatStackFrameParameters(&sb, trace.Params)
		}
	}

	return sb.String()
}

func formatStackFrameParameters(sb *strings.Builder, params map[string]interface{}) {
	if len(params) == 0 {
		return
	}
	var sortedKeys []string
	for k := range params {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		_, _ = sb.WriteString(fmt.Sprintf("\t- %s: %s\n", k, logentryformatter.FormatValue(params[k])))
	}
}

func extractThreadName(threadID *string, unsafeParams map[string]interface{}) string {
	if threadID == nil {
		return ""
	}

	if strings.HasPrefix(*threadID, "{") && strings.HasSuffix(*threadID, "}") {
		realThreadID := strings.Trim(*threadID, "{}")
		if threadName, ok := unsafeParams[realThreadID]; ok {
			if threadNameStr, ok := threadName.(string); ok {
				return threadNameStr
			}
		}
	}
	return *threadID
}
