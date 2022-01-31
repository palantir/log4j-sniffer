// Copyright (c) 2022 Palantir Technologies. All rights reserved.
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

package log

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

type Logger struct {
	OutputWriter       io.Writer
	ErrorWriter        io.Writer
	EnableTraceLogging bool
}

func (i Logger) Trace(format string, args ...interface{}) {
	if i.OutputWriter != nil && i.EnableTraceLogging {
		_, _ = fmt.Fprintln(i.OutputWriter, fmt.Sprintf("[TRACE] "+format, args...))
	}
}

func (i Logger) Info(format string, args ...interface{}) {
	if i.OutputWriter != nil {
		_, _ = fmt.Fprintln(i.OutputWriter, color.CyanString("[INFO] "+format, args...))
	}
}

func (i Logger) Error(format string, args ...interface{}) {
	if i.ErrorWriter != nil {
		_, _ = fmt.Fprintln(i.ErrorWriter, color.RedString("[ERROR] "+format, args...))
	}
}
