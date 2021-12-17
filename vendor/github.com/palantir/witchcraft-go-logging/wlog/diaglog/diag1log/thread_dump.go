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

package diag1log

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/palantir/pkg/safelong"
	"github.com/palantir/witchcraft-go-logging/conjure/witchcraft/api/logging"
	"github.com/palantir/witchcraft-go-logging/internal/gopath"
)

// ThreadDumpV1FromGoroutines unmarshals a "goroutine dump" (as formatted by panic or the runtime package)
// and returns a conjured logging.ThreadDumpV1 object.
func ThreadDumpV1FromGoroutines(goroutinesContent []byte) logging.ThreadDumpV1 {
	// Goroutines are separated by an empty line
	goroutines := bytes.Split(goroutinesContent, []byte("\n\n"))

	threads := logging.ThreadDumpV1{Threads: make([]logging.ThreadInfoV1, len(goroutines))}
	for i, goroutine := range goroutines {
		threads.Threads[i] = unmarshalThreadDump(goroutine)
	}
	return threads
}

var titleLinePattern = regexp.MustCompile(`^(goroutine (\d+) \[([^]]+)]):$`)

func unmarshalThreadDump(goroutine []byte) logging.ThreadInfoV1 {
	lines := bytes.Split(bytes.TrimSpace(goroutine), []byte("\n"))
	if len(lines) == 0 {
		return logging.ThreadInfoV1{}
	}

	info := logging.ThreadInfoV1{Params: make(map[string]interface{})}

	// The first line is of the form 'goroutine 14 [select]:'
	titleLine := string(lines[0])
	if matches := titleLinePattern.FindStringSubmatch(titleLine); len(matches) >= 4 {
		info.Name = stringPtr(matches[1])
		info.Id = stringToOptionalSafeLong(matches[2])
		info.Params["status"] = matches[3]
	}

	// Stack frames start with the 2nd line
	stackLines := lines[1:]
	// Go through stack frames two lines at a time
	for i := 0; i < len(stackLines); i += 2 {
		funcLine := stackLines[i]
		fileLine := stackLines[i+1]

		frame := logging.StackFrameV1{Params: make(map[string]interface{})}

		unmarshalFuncLine(funcLine, &frame)
		unmarshalFileLine(fileLine, &frame)

		info.StackTrace = append(info.StackTrace, frame)
	}

	return info
}

func unmarshalFuncLine(funcLine []byte, frame *logging.StackFrameV1) {
	if bytes.HasPrefix(funcLine, []byte("created by ")) {
		// creators do not include arguments
		procedure := strings.TrimPrefix(string(funcLine), "created by ")
		frame.Procedure = &procedure
		frame.Params["goroutineCreator"] = true
		return
	}

	argIndex := bytes.LastIndex(funcLine, []byte("("))
	if argIndex != -1 {
		procedure := string(funcLine[:argIndex])
		frame.Procedure = &procedure
	}
}

func unmarshalFileLine(fileLine []byte, frame *logging.StackFrameV1) {
	segments := strings.Split(string(bytes.TrimSpace(fileLine)), " +")

	if len(segments) > 1 {
		frame.Address = &segments[1]
	}

	sepIdx := strings.LastIndex(segments[0], ":")

	if sepIdx > -1 {
		absPath := segments[0][:sepIdx]
		file := gopath.TrimPrefix(absPath)
		frame.File = &file
	}

	if sepIdx+1 < len(segments[0]) {
		lineNumStr := segments[0][sepIdx+1:]
		lineNum, err := strconv.Atoi(lineNumStr)
		if err == nil {
			frame.Line = &lineNum
		}
	}
}

func stringPtr(s string) *string {
	return &s
}

// stringToOptionalSafeLong returns nil on errors
func stringToOptionalSafeLong(s string) *safelong.SafeLong {
	i, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return nil
	}
	long, err := safelong.NewSafeLong(i)
	if err != nil {
		return nil
	}
	return &long
}
