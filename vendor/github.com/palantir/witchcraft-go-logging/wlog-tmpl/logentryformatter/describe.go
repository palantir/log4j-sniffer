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
	"reflect"
	"strings"
	"text/tabwriter"
)

func DescribeObject(obj interface{}) string {
	const jsonCol = "JSON Field"
	const descCol = "Description"

	nonEmptyFields := make(map[string]struct{})
	var rows []*reflect.StructField
	st := reflect.TypeOf(obj)
	for i := 0; i < st.NumField(); i++ {
		stField := st.Field(i)
		rows = append(rows, &stField)
		if jsonName := structFieldJSONName(&stField); jsonName != "" {
			nonEmptyFields[jsonCol] = struct{}{}
		}
		if docs := structFieldConjureDocs(&stField); docs != "" {
			nonEmptyFields[descCol] = struct{}{}
		}
	}

	cols := []string{"Name", "Type"}
	if _, ok := nonEmptyFields[jsonCol]; ok {
		cols = append(cols, jsonCol)
	}
	if _, ok := nonEmptyFields[descCol]; ok {
		cols = append(cols, descCol)
	}

	buf := &bytes.Buffer{}
	tw := tabwriter.NewWriter(buf, 0, 4, 4, ' ', 0)
	_, _ = fmt.Fprintln(tw, strings.Join(cols, "\t"))

	colLines := make([]string, len(cols))
	for i, v := range cols {
		colLines[i] = strings.Repeat("-", len(v))
	}
	_, _ = fmt.Fprintln(tw, strings.Join(colLines, "\t"))
	for _, curr := range rows {
		parts := []string{structFieldName(curr), structFieldType(curr)}
		if _, ok := nonEmptyFields[jsonCol]; ok {
			jsonName := structFieldJSONName(curr)
			if jsonName == "" {
				jsonName = "-"
			}
			parts = append(parts, jsonName)
		}

		var docsLines []string
		if _, ok := nonEmptyFields[descCol]; ok {
			conjureDocs := structFieldConjureDocs(curr)
			if conjureDocs == "" {
				conjureDocs = "-"
			}
			docsLines = strings.Split(conjureDocs, "\n")
			parts = append(parts, docsLines[0])
		}
		_, _ = fmt.Fprintln(tw, strings.Join(parts, "\t"))

		for i := 1; i < len(docsLines); i++ {
			// if docs column had multiple lines, first was appended to the initial row but rest were not.
			// Go through the rest and append them as their own rows. Assumes that "docs" column is the
			// final column
			for colIdx := range parts {
				parts[colIdx] = ""
			}
			parts[len(parts)-1] = docsLines[i]
			_, _ = fmt.Fprintln(tw, strings.Join(parts, "\t"))
		}
	}
	_ = tw.Flush()
	return strings.TrimRight(buf.String(), "\n")
}

func structFieldName(sf *reflect.StructField) string {
	return sf.Name
}

func structFieldType(sf *reflect.StructField) string {
	return sf.Type.String()
}

func structFieldJSONName(sf *reflect.StructField) string {
	jsonTag := sf.Tag.Get("json")
	if jsonTag == "" {
		return ""
	}
	return strings.Split(jsonTag, ",")[0]
}

func structFieldConjureDocs(sf *reflect.StructField) string {
	conjureDocsTag := sf.Tag.Get("conjure-docs")
	if conjureDocsTag == "" {
		return ""
	}
	return conjureDocsTag
}
