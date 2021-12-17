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
	"github.com/palantir/witchcraft-go-tracing/wtracing"
)

type wrappedLogger struct {
	logger Logger
	params []Param
}

func (w *wrappedLogger) Log(span wtracing.SpanModel, params ...Param) {
	w.logger.Log(span, append(w.params, params...)...)
}

func (w *wrappedLogger) Send(span wtracing.SpanModel) {
	w.logger.Log(span, w.params...)
}

func (w *wrappedLogger) Close() error {
	return w.logger.Close()
}
