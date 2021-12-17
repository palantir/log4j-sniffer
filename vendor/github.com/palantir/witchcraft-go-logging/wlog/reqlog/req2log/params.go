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

import (
	"github.com/palantir/witchcraft-go-logging/wlog"
	"github.com/palantir/witchcraft-go-logging/wlog/extractor"
)

type LoggerCreatorParam interface {
	Apply(builder LoggerBuilder)
}

type loggerCreatorParamFunc func(builder LoggerBuilder)

func (f loggerCreatorParamFunc) Apply(builder LoggerBuilder) {
	f(builder)
}

func Creator(creator wlog.LoggerCreator) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.LoggerCreator(creator)
	})
}

func Extractor(extractor extractor.IDsFromRequest) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.IdsExtractor(extractor)
	})
}

func SafePathParams(safeParams ...string) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.SafePathParams(safeParams)
	})
}

func ForbiddenPathParams(forbiddenParams ...string) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.ForbiddenPathParams(forbiddenParams)
	})
}

func SafeQueryParams(safeParams ...string) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.SafeQueryParams(safeParams)
	})
}

func ForbiddenQueryParams(forbiddenParams ...string) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.ForbiddenQueryParams(forbiddenParams)
	})
}

func SafeHeaderParams(safeParams ...string) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.SafeHeaderParams(safeParams)
	})
}

func ForbiddenHeaderParams(forbiddenParams ...string) LoggerCreatorParam {
	return loggerCreatorParamFunc(func(builder LoggerBuilder) {
		builder.ForbiddenHeaderParams(forbiddenParams)
	})
}
