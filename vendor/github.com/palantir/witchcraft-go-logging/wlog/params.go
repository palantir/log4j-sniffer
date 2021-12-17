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

package wlog

type Param interface {
	apply(logger LogEntry)
}

func StringParam(key, value string) Param {
	return NewParam(func(logger LogEntry) {
		logger.StringValue(key, value)
	})
}

func OptionalStringParam(key, value string) Param {
	return NewParam(func(logger LogEntry) {
		logger.OptionalStringValue(key, value)
	})
}

func IntParam(key string, value int32) Param {
	return NewParam(func(logger LogEntry) {
		logger.IntValue(key, value)
	})
}

func Int64Param(key string, value int64) Param {
	return NewParam(func(logger LogEntry) {
		logger.SafeLongValue(key, value)
	})
}

func NewParam(fn func(entry LogEntry)) Param {
	return paramFunc(fn)
}

func ApplyParams(logger LogEntry, params []Param) {
	for _, p := range params {
		if p == nil {
			continue
		}
		p.apply(logger)
	}
}

// ParamsWithMessage returns a new slice that appends a StringParam with the key "message" and
// value of the provided msg parameter if it is non-empty. If msg is empty, returns the provided slice
// without modification.
func ParamsWithMessage(msg string, params []Param) []Param {
	if msg != "" {
		return append(params, StringParam("message", msg))
	}
	return params
}

type paramFunc func(logger LogEntry)

func (f paramFunc) apply(logger LogEntry) {
	f(logger)
}
