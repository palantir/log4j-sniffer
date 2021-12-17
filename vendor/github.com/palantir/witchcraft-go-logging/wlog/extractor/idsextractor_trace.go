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

package extractor

import (
	"net/http"
)

const (
	TraceIDKey = "traceId"
)

// newTraceIDFromHeaderExtractor returns a map with the TraceIDKey key with the value stored in the "X-B3-TraceId"
// header of the request.
func newTraceIDFromHeaderExtractor() IDsFromRequest {
	return &traceIDExtractor{}
}

type traceIDExtractor struct{}

func (e *traceIDExtractor) ExtractIDs(req *http.Request) map[string]string {
	return map[string]string{
		TraceIDKey: req.Header.Get("X-B3-TraceId"),
	}
}
