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
	"encoding/json"
	"fmt"

	"github.com/palantir/witchcraft-go-logging/wlog-tmpl/logentryformatter"
)

var wrapped1Unwrapper = logentryformatter.UnwrapperFunc(unwrapWrappedV1)

func unwrapWrappedV1(lineJSON []byte) ([]byte, error) {
	var unwrapped wrappedLogV1Payload
	if err := json.Unmarshal(lineJSON, &unwrapped); err != nil {
		return nil, fmt.Errorf("failed to unmarshal wrapped.1 entry as JSON: %v", err)
	}
	return unwrapped.Contents, nil
}

type wrappedLogV1Payload struct {
	Type     logentryformatter.LogType
	Contents []byte
}

// UnmarshalJSON returns the deserialized wrapped.1 payload. It defers
// unmarshalling of the payload to avoid the extra cost of unmarshalling and
// remarshalling the payload contents, which is unavoidable when using the
// conjure generated code.
func (p *wrappedLogV1Payload) UnmarshalJSON(data []byte) error {
	type payload struct {
		Type            logentryformatter.LogType `json:"type"`
		ServiceLogV1    json.RawMessage           `json:"serviceLogV1"`
		RequestLogV2    json.RawMessage           `json:"requestLogV2"`
		TraceLogV1      json.RawMessage           `json:"traceLogV1"`
		EventLogV2      json.RawMessage           `json:"eventLogV2"`
		MetricLogV1     json.RawMessage           `json:"metricLogV1"`
		AuditLogV2      json.RawMessage           `json:"auditLogV2"`
		DiagnosticLogV1 json.RawMessage           `json:"diagnosticLogV1"`
	}
	var wrapped1LogEntry struct {
		payload `json:"payload"`
	}
	if err := json.Unmarshal(data, &wrapped1LogEntry); err != nil {
		return err
	}
	switch wrapped1LogEntry.Type {
	default:
	case "serviceLogV1":
		p.Contents = wrapped1LogEntry.ServiceLogV1
	case "requestLogV2":
		p.Contents = wrapped1LogEntry.RequestLogV2
	case "traceLogV1":
		p.Contents = wrapped1LogEntry.TraceLogV1
	case "eventLogV2":
		p.Contents = wrapped1LogEntry.EventLogV2
	case "metricLogV1":
		p.Contents = wrapped1LogEntry.MetricLogV1
	case "auditLogV2":
		p.Contents = wrapped1LogEntry.AuditLogV2
	case "diagnosticLogV1":
		p.Contents = wrapped1LogEntry.DiagnosticLogV1
	}
	return nil
}
