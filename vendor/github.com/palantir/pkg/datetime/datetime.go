// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package datetime

import (
	"strings"
	"time"
)

// DateTime is an alias for time.Time which implements serialization matching the
// conjure wire specification at https://github.com/palantir/conjure/blob/master/docs/spec/wire.md
type DateTime time.Time

func (d DateTime) String() string {
	return time.Time(d).Format(time.RFC3339Nano)
}

// MarshalText implements encoding.TextMarshaler (used by encoding/json and others).
func (d DateTime) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler (used by encoding/json and others).
func (d *DateTime) UnmarshalText(b []byte) error {
	t, err := ParseDateTime(string(b))
	if err != nil {
		return err
	}
	*d = t
	return nil
}

// ParseDateTime parses a DateTime from a string. Conjure supports DateTime inputs that end with an optional
// zone identifier enclosed in square brackets (for example, "2017-01-02T04:04:05.000000000+01:00[Europe/Berlin]").
func ParseDateTime(s string) (DateTime, error) {
	// If the input string ends in a ']' and contains a '[', parse the string up to '['.
	if strings.HasSuffix(s, "]") {
		if openBracketIdx := strings.LastIndex(s, "["); openBracketIdx != -1 {
			s = s[:openBracketIdx]
		}
	}
	timeVal, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return DateTime(time.Time{}), err
	}
	return DateTime(timeVal), nil
}
