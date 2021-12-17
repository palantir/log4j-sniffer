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

package trc1log

import (
	"time"

	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-tracing/wtracing"
)

type defaultLogger struct {
	logger wlog.Logger
}

func (l *defaultLogger) Log(span wtracing.SpanModel, params ...Param) {
	l.logger.Log(ToParams(span, params)...)
}

func ToParams(span wtracing.SpanModel, inParams []Param) []wlog.Param {
	outParams := make([]wlog.Param, len(inParams))
	for idx := range inParams {
		outParams[idx] = wlog.NewParam(inParams[idx].apply)
	}
	return append([]wlog.Param{
		wlog.NewParam(func(entry wlog.LogEntry) {
			entry.StringValue(wlog.TypeKey, TypeValue)
			entry.StringValue(wlog.TimeKey, time.Now().Format(time.RFC3339Nano))
		}),
		spanParam(span),
	}, outParams...)
}

func (l *defaultLogger) Send(span wtracing.SpanModel) {
	l.Log(span)
}

func (l *defaultLogger) Close() error {
	return nil
}

func spanParam(span wtracing.SpanModel) wlog.Param {
	return wlog.NewParam(func(entry wlog.LogEntry) {
		spanEntry := wlog.NewMapLogEntry()
		spanEntry.StringValue(wlog.TraceIDKey, string(span.TraceID))
		spanEntry.StringValue(SpanIDKey, string(span.ID))
		spanEntry.StringValue(SpanNameKey, span.Name)

		if parentID := span.ParentID; parentID != nil {
			spanEntry.StringValue(SpanParentIDKey, string(*parentID))
		}
		spanEntry.SafeLongValue(SpanTimestampKey, span.Timestamp.Round(time.Microsecond).UnixNano()/1e3)
		spanEntry.SafeLongValue(SpanDurationKey, int64(span.Duration/time.Microsecond))

		if kind := span.Kind; kind != "" {
			switch kind {
			case wtracing.Server:
				wlog.ApplyParams(spanEntry, []wlog.Param{spanAnnotationsParam("sr", "ss", span)})
			case wtracing.Client:
				wlog.ApplyParams(spanEntry, []wlog.Param{spanAnnotationsParam("cs", "cr", span)})
			}
		}

		if tags := span.Tags; len(tags) > 0 {
			spanEntry.StringMapValue(SpanTagsKey, tags)
		}
		entry.AnyMapValue(SpanKey, spanEntry.AllValues())
	})
}

func spanAnnotationsParam(startVal, endVal string, span wtracing.SpanModel) wlog.Param {
	return wlog.NewParam(func(entry wlog.LogEntry) {
		entry.ObjectValue(SpanAnnotationsKey, []map[string]interface{}{
			spanAnnotationFields(startVal, span.Timestamp, span.LocalEndpoint),
			spanAnnotationFields(endVal, span.Timestamp.Add(span.Duration), span.LocalEndpoint),
		}, nil)
	})
}

func spanAnnotationFields(value string, timeStamp time.Time, endpoint *wtracing.Endpoint) map[string]interface{} {
	fields := make(map[string]interface{})
	fields[AnnotationValueKey] = value
	fields[AnnotationTimestampKey] = timeStamp.Round(time.Microsecond).UnixNano() / time.Microsecond.Nanoseconds()
	if endpoint != nil {
		endpointFields := map[string]string{
			EndpointServiceNameKey: endpoint.ServiceName,
		}
		if len(endpoint.IPv4) > 0 {
			endpointFields[EndpointIPv4Key] = endpoint.IPv4.String()
		}
		if len(endpoint.IPv6) > 0 {
			endpointFields[EndpointIPv6Key] = endpoint.IPv6.String()
		}
		fields[AnnotationEndpointKey] = endpointFields
	}
	return fields
}
