// Copyright (c) 2019 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safeyaml

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v2"
)

// JSONtoYAMLMapSlice decodes JSON bytes into an interface{} where all objects and maps are decoded
// as a yaml.MapSlice to preserve key ordering. This can be useful if a type defines custom JSON
// marshal logic and translating the JSON representation to a YAML representation while
// preserving key ordering is sufficient for serialization. For example:
//
//	func (o Foo) MarshalYAML() (interface{}, error) {
//		jsonBytes, err := json.Marshal(o)
//		if err != nil {
//			return nil, err
//		}
//		return JSONtoYAML(jsonBytes)
//	}
func JSONtoYAMLMapSlice(jsonBytes []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	val, err := tokenizerToYAML(dec)
	if err != nil {
		return val, err
	}
	if dec.More() {
		return nil, fmt.Errorf("invalid input after top-level JSON value")
	}
	return val, nil
}

// JSONtoYAMLBytes converts json data to yaml output while preserving order of object fields.
func JSONtoYAMLBytes(jsonBytes []byte) ([]byte, error) {
	obj, err := JSONtoYAMLMapSlice(jsonBytes)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(obj)
}

var errClosingArrayDelim = fmt.Errorf("unexpected ']' delimiter")
var errClosingObjectDelim = fmt.Errorf("unexpected '}' delimiter")

func tokenizerToYAML(dec *json.Decoder) (interface{}, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}
	switch v := tok.(type) {
	case string, bool, float64:
		return v, nil
	case json.Number:
		if numI, err := v.Int64(); err == nil {
			return numI, nil
		}
		if numF, err := v.Float64(); err == nil {
			return numF, nil
		}
		return v.String(), nil
	case json.Delim:
		switch v {
		case '[':
			arr := make([]interface{}, 0)
			for {
				elem, err := tokenizerToYAML(dec)
				if err == errClosingArrayDelim {
					break
				}
				if err != nil {
					return nil, err
				}
				arr = append(arr, elem)
			}
			return arr, nil
		case '{':
			obj := make(yaml.MapSlice, 0)
			for {
				objectKeyI, err := tokenizerToYAML(dec)
				if err == errClosingObjectDelim {
					break
				}
				if err != nil {
					return nil, err
				}
				objectValueI, err := tokenizerToYAML(dec)
				if err != nil {
					return nil, err
				}
				obj = append(obj, yaml.MapItem{Key: objectKeyI, Value: objectValueI})
			}
			return obj, nil
		case ']':
			return nil, errClosingArrayDelim
		case '}':
			return nil, errClosingObjectDelim
		default:
			return nil, fmt.Errorf("unrecognized delimiter")
		}
	default:
		return nil, fmt.Errorf("unrecognized token type %T", tok)
	}
}
