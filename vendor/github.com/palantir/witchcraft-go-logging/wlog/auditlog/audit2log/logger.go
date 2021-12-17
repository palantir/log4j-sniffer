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

package audit2log

import (
	"io"

	"github.com/palantir/witchcraft-go-logging/wlog"
)

type AuditResultType string

const (
	AuditResultSuccess      AuditResultType = "SUCCESS"
	AuditResultUnauthorized AuditResultType = "UNAUTHORIZED"
	AuditResultError        AuditResultType = "ERROR"
)

type Logger interface {
	Audit(name string, result AuditResultType, params ...Param)
}

func New(w io.Writer) Logger {
	return NewFromCreator(w, wlog.DefaultLoggerProvider().NewLogger)
}

func NewFromCreator(w io.Writer, creator wlog.LoggerCreator) Logger {
	return &defaultLogger{
		logger: creator(w),
	}
}

func WithParams(logger Logger, params ...Param) Logger {
	if len(params) == 0 {
		return logger
	}

	if innerWrapped, ok := logger.(*wrappedLogger); ok {
		return &wrappedLogger{
			logger: innerWrapped.logger,
			params: append(innerWrapped.params, params...),
		}
	}

	return &wrappedLogger{
		logger: logger,
		params: params,
	}
}
