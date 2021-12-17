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
	"fmt"
	"sort"
	"strconv"
	"text/template"
)

type Param interface {
	apply(*entryFormatter)
}

type paramFunc func(*entryFormatter)

func (f paramFunc) apply(ef *entryFormatter) {
	f(ef)
}

func Colorizer(c ColorizerFunc) Param {
	return paramFunc(func(f *entryFormatter) {
		f.colorizer = c
	})
}

func ObjDesc(objDesc string) Param {
	return paramFunc(func(f *entryFormatter) {
		f.objDesc = objDesc
	})
}

// NoSubstitution configures the formatter in a mode that specifies that no substitution should be performed.
func NoSubstitution() Param {
	return paramFunc(func(f *entryFormatter) {
		f.noSubstitution = true
	})
}

func New(entryParser func([]byte, bool) (interface{}, error), tmplString string, params ...Param) (Formatter, error) {
	tmpl := template.New("logFunc")
	tmpl.Funcs(map[string]interface{}{
		"niceMap":    NiceMap,
		"niceMapStr": niceMapStr,
	})
	tmpl, err := tmpl.Parse(tmplString)
	if err != nil {
		return nil, err
	}
	f := &entryFormatter{
		entryParser: entryParser,
		tmpl:        tmpl,
		rawTemplate: tmplString,
	}
	for _, p := range params {
		if p == nil {
			continue
		}
		p.apply(f)
	}
	return f, nil
}

func NiceMap(params map[string]interface{}) string {
	if len(params) == 0 {
		return ""
	}

	var sortedKeys []string
	for k := range params {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	buf := &bytes.Buffer{}
	fmt.Fprint(buf, "(")
	for i, k := range sortedKeys {
		fmt.Fprintf(buf, "%s: %s", k, FormatValue(params[k]))
		if i != len(params)-1 {
			fmt.Fprint(buf, ", ")
		}
	}
	fmt.Fprint(buf, ")")
	return buf.String()
}

func niceMapStr(params map[string]string) string {
	mapIface := make(map[string]interface{}, len(params))
	for k, v := range params {
		mapIface[k] = v
	}
	return NiceMap(mapIface)
}

func FormatValue(val interface{}) string {
	switch v := val.(type) {
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
