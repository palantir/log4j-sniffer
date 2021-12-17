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

package req2log

var defaultRequestParamPerms RequestParamPerms = &requestParamPermsImpl{
	headerParamPerms: NewParamPerms(
		[]string{
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Accept-Ranges",
			"Cache-Control",
			"Connection",
			"Content-Length",
			"Content-Security-Policy",
			"Content-Type",
			"Date",
			"ETag",
			"Expires",
			"Fetch-User-Agent",
			"Host",
			"If-Modified-Since",
			"If-None-Match",
			"Last-Modified",
			"Origin",
			"Pragma",
			"Server",
			"Transfer-Encoding",
			"User-Agent",
			"Vary",
			"X-B3-ParentSpanId",
			"X-B3-Sampled",
			"X-B3-SpanId",
			"X-B3-TraceId",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-XSS-Protection",
		},
		[]string{
			"Authorization",
			"Cookie",
			"Set-Cookie",
			"Set-Cookie2",
		},
	),
}

func DefaultRequestParamPerms() RequestParamPerms {
	return defaultRequestParamPerms
}

func SetRequestParamPerms(perms RequestParamPerms) {
	defaultRequestParamPerms = perms
}

type requestParamPermsImpl struct {
	pathParamPerms   ParamPerms
	queryParamPerms  ParamPerms
	headerParamPerms ParamPerms
}

func (r *requestParamPermsImpl) PathParamPerms() ParamPerms {
	return r.pathParamPerms
}

func (r *requestParamPermsImpl) QueryParamPerms() ParamPerms {
	return r.queryParamPerms
}

func (r *requestParamPermsImpl) HeaderParamPerms() ParamPerms {
	return r.headerParamPerms
}
