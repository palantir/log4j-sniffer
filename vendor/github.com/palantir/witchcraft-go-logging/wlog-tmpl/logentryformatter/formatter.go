// Copyright (c) 2020 Palantir Technologies. All rights reserved.
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

package logentryformatter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/template"

	"github.com/fatih/color"
)

var defaultColorizer = color.New()

type LogType string

type LogEntry struct {
	Type *LogType `json:"type"`
}

func FormatLogLine(text string, unwrapperMap map[LogType]Unwrapper, formatterMap map[LogType]Formatter, only, exclude map[LogType]struct{}) (string, error) {
	lineJSON, err := getJSONLine([]byte(text))
	if err != nil {
		return "", err
	}
	logType, err := parseLogType(lineJSON)
	if err != nil {
		return "", err
	}
	if unwrapper, ok := unwrapperMap[logType]; ok {
		contents, err := unwrapper.UnwrapLogLine(lineJSON)
		if err != nil {
			return "", fmt.Errorf("Failed to unwrap log line type: %s", logType)
		}
		lineJSON = contents
		logType, err = parseLogType(lineJSON)
		if err != nil {
			return "", err
		}
	}
	if _, exclude := exclude[logType]; exclude {
		// return empty if log type was specified as exclude
		return "", nil
	}
	if _, include := only[logType]; len(only) > 0 && !include {
		// return empty if include list is non-empty and this log type is not in the include list
		return "", nil
	}
	formatter, ok := formatterMap[logType]
	if !ok {
		return "", fmt.Errorf("Skipping unknown log line type: %s", logType)
	}
	return formatter.Format(lineJSON)
}

// An Unwrapper unwraps a line of JSON, returning the underlying log entry's
// contents.
type Unwrapper interface {
	UnwrapLogLine(lineJSON []byte) ([]byte, error)
}

// The UnwrapperFunc type is an adapter to allow the use of ordinary functions
// as Unwrappers. If f is a function with the appropriate signature,
// UnwrapperFunc(f) is an Unwrapper that calls f.
type UnwrapperFunc func([]byte) ([]byte, error)

// UnwrapLogLine calls f(lineJSON).
func (f UnwrapperFunc) UnwrapLogLine(lineJSON []byte) ([]byte, error) {
	return f(lineJSON)
}

type Formatter interface {
	// Format takes JSON bytes that represents a single log entry and returns the human-readable version.
	Format(lineJSON []byte) (string, error)
	// RawTemplate returns the raw template string for this formatter.
	RawTemplate() string
	// TemplateObjectDescription returns the description of the object that is expected to be provided to the
	// template function for this formatter. Empty string indicates that there is no suitable description.
	TemplateObjectDescription() string
}

type ColorizerFunc func(interface{}) *color.Color

type entryFormatter struct {
	entryParser    func(lineJSON []byte, substitute bool) (interface{}, error)
	colorizer      ColorizerFunc
	tmpl           *template.Template
	objDesc        string
	rawTemplate    string
	noSubstitution bool
}

func (f *entryFormatter) Format(lineJSON []byte) (string, error) {
	obj, err := f.entryParser(lineJSON, !f.noSubstitution)
	if err != nil {
		return "", err
	}

	buf := &bytes.Buffer{}
	if err := f.tmpl.Execute(buf, obj); err != nil {
		return "", err
	}

	logText := buf.String()
	// if log text is empty, return directly (don't colorize)
	if logText == "" {
		return logText, nil
	}

	if f.colorizer != nil {
		if c := f.colorizer(obj); c != nil {
			return c.Sprint(logText), nil
		}
	}
	return defaultColorizer.Sprint(logText), nil
}

func (f *entryFormatter) TemplateObjectDescription() string {
	return f.objDesc
}

func (f *entryFormatter) RawTemplate() string {
	return f.rawTemplate
}

func getJSONLine(line []byte) ([]byte, error) {
	jsonStart := bytes.Index(line, []byte("{"))
	if jsonStart == -1 {
		return nil, fmt.Errorf("Log line %q is not valid JSON", line)
	}
	return line[jsonStart:], nil
}

func parseLogType(line []byte) (LogType, error) {
	var res LogEntry
	if err := json.Unmarshal(line, &res); err != nil {
		return "", fmt.Errorf("Failed to parse log line %q as JSON: %v", line, err)
	}
	if res.Type == nil {
		return "", fmt.Errorf("Log line JSON %q does not have a \"type\" key so its log type cannot be determined", line)
	}
	return *res.Type, nil
}
