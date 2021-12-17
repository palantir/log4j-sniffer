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

package wloginternal

import (
	"fmt"
	"runtime"
	"strings"
)

// WarnLoggerOutput returns the logger output for a default warning logger for a given logger type. The output includes
// the location at which the call was made, with the "skip" parameter determining how far back in the call stack to go
// for the location (for example, skip=0 specifies the line in this function, skip=1 specifies the line that called this
// function, etc.).
//
// This function is defined in an internal package because each logger type needs to define its own warning logger type
// but the format/content of the output should be consistent across them.
func WarnLoggerOutput(loggerType, output string, skip int) string {
	pc, fn, line, _ := runtime.Caller(skip)
	return fmt.Sprintf("[WARNING] %s[%s:%d]: usage of %s.Logger from FromContext that did not have that logger set: %s", runtime.FuncForPC(pc).Name(), fn, line, loggerType, strings.TrimSuffix(output, "\n"))
}
