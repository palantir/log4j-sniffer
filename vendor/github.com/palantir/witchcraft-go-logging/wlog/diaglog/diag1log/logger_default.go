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

package diag1log

import (
	"fmt"
	"time"

	"github.com/palantir/witchcraft-go-logging/conjure/witchcraft/api/logging"
	"github.com/palantir/witchcraft-go-logging/wlog"
)

type defaultLogger struct {
	logger wlog.Logger
}

func (l *defaultLogger) Diagnostic(diagnostic logging.Diagnostic, params ...Param) {
	l.logger.Log(ToParams(diagnostic, params)...)
}

func ToParams(diagnostic logging.Diagnostic, inParams []Param) []wlog.Param {
	outParams := make([]wlog.Param, len(defaultTypeParam)+1+len(inParams))
	copy(outParams, defaultTypeParam)
	outParams[len(defaultTypeParam)] = diagnosticParam(diagnostic)
	for idx := range inParams {
		outParams[len(defaultTypeParam)+1+idx] = wlog.NewParam(inParams[idx].apply)
	}
	return outParams
}

func diagnosticParam(diagnostic logging.Diagnostic) wlog.Param {
	visitor := &diagnosticVisitor{}
	_ = diagnostic.Accept(visitor)
	if visitor.diagnosticParam != nil {
		return visitor.diagnosticParam
	}
	return wlog.NewParam(func(entry wlog.LogEntry) {})
}

type diagnosticVisitor struct {
	diagnosticParam wlog.Param
}

func (d *diagnosticVisitor) VisitGeneric(v logging.GenericDiagnostic) error {
	d.diagnosticParam = wlog.NewParam(func(entry wlog.LogEntry) {
		entry.AnyMapValue("diagnostic", map[string]interface{}{
			"type": "generic",
			"generic": map[string]interface{}{
				"diagnosticType": v.DiagnosticType,
				"value":          v.Value,
			},
		})
	})
	return nil
}

func (d *diagnosticVisitor) VisitThreadDump(v logging.ThreadDumpV1) error {
	d.diagnosticParam = wlog.NewParam(func(entry wlog.LogEntry) {
		entry.AnyMapValue("diagnostic", map[string]interface{}{
			"type": "threadDump",
			"threadDump": map[string]interface{}{
				"threads": threadsField(v.Threads),
			},
		})
	})
	return nil
}

func (d *diagnosticVisitor) VisitUnknown(typeName string) error {
	return fmt.Errorf("unknown diagnostic type: %s", typeName)
}

func threadsField(threads []logging.ThreadInfoV1) []map[string]interface{} {
	encodedThreads := make([]map[string]interface{}, len(threads))
	for idx, threadInfo := range threads {
		encodedThreads[idx] = encodeThreadInfo(threadInfo)
	}
	return encodedThreads
}

func encodeThreadInfo(threadInfo logging.ThreadInfoV1) map[string]interface{} {
	fields := make(map[string]interface{})
	if threadInfo.Id != nil {
		fields["id"] = threadInfo.Id
	}
	encodeNonEmptyString(fields, "name", threadInfo.Name)
	if len(threadInfo.StackTrace) > 0 {
		fields["stackTrace"] = stackTraceField(threadInfo.StackTrace)
	}
	if len(threadInfo.Params) > 0 {
		fields["params"] = threadInfo.Params
	}
	return fields
}

func stackTraceField(stackFrames []logging.StackFrameV1) []map[string]interface{} {
	encodedStackTrace := make([]map[string]interface{}, len(stackFrames))
	for idx, stackFrame := range stackFrames {
		encodedStackTrace[idx] = encodeStackFrame(stackFrame)
	}
	return encodedStackTrace
}

func encodeStackFrame(stackFrame logging.StackFrameV1) map[string]interface{} {
	fields := make(map[string]interface{})
	encodeNonEmptyString(fields, "address", stackFrame.Address)
	encodeNonEmptyString(fields, "procedure", stackFrame.Procedure)
	encodeNonEmptyString(fields, "file", stackFrame.File)
	if stackFrame.Line != nil {
		fields["line"] = stackFrame.Line
	}
	if len(stackFrame.Params) > 0 {
		fields["params"] = stackFrame.Params
	}
	return fields
}

func encodeNonEmptyString(fields map[string]interface{}, key string, val *string) {
	if val == nil || len(*val) == 0 {
		return
	}
	fields[key] = val
}

var defaultTypeParam = []wlog.Param{
	wlog.NewParam(func(entry wlog.LogEntry) {
		entry.StringValue(wlog.TypeKey, TypeValue)
		entry.StringValue(wlog.TimeKey, time.Now().Format(time.RFC3339Nano))
	}),
}
