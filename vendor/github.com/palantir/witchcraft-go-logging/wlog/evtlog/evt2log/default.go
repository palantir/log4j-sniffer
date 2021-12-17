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

package evt2log

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/palantir/witchcraft-go-logging/wlog"
	wloginternal "github.com/palantir/witchcraft-go-logging/wlog/internal"
)

func SetDefaultLoggerCreator(creator func() Logger) {
	defaultLoggerCreator = creator
}

var defaultLoggerCreator = func() Logger {
	return &warnLogger{
		w: os.Stderr,
		// store the DefaultLoggerProvider at creation-time so that the output of this logger will be consistent
		// throughout its lifetime (if the default logger provider is changed after a specific warnLogger is created,
		// that should not change the creator used for that warnLogger).
		creator: wlog.DefaultLoggerProvider().NewLogger,
	}
}

// warnLogger is a logger that writes a warning to the provided io.Writer whenever its logging function is invoked. When
// the logging function is invoked, a new logger is created using the wlog.LoggerCreator and a warning and the output of
// the created logger are written to the io.Writer.
type warnLogger struct {
	w       io.Writer
	creator wlog.LoggerCreator
}

func (l *warnLogger) Event(name string, params ...Param) {
	buf := &bytes.Buffer{}
	NewFromCreator(buf, l.creator).Event(name, params...)
	_, _ = fmt.Fprintln(l.w, wloginternal.WarnLoggerOutput("evt2log", buf.String(), 2))
}
