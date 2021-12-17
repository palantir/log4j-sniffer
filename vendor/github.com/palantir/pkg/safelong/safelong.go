// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safelong

import (
	"encoding/json"
	"fmt"
	"strconv"
)

const (
	safeIntVal = int64(1) << 53
	minVal     = -safeIntVal + 1
	maxVal     = safeIntVal - 1
)

type SafeLong int64

func NewSafeLong(val int64) (SafeLong, error) {
	if err := validate(val); err != nil {
		return 0, err
	}
	return SafeLong(val), nil
}

func ParseSafeLong(s string) (SafeLong, error) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return NewSafeLong(i)
}

func (s *SafeLong) UnmarshalJSON(b []byte) error {
	var val int64
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	}

	newVal, err := NewSafeLong(val)
	if err != nil {
		return err
	}
	*s = newVal

	return nil
}

func (s SafeLong) MarshalJSON() ([]byte, error) {
	if err := validate(int64(s)); err != nil {
		return nil, err
	}
	return json.Marshal(int64(s))
}

func validate(val int64) error {
	if val < minVal || val > maxVal {
		return fmt.Errorf("%d is not a valid value for a SafeLong as it is not safely representable in Javascript: must be between %d and %d", val, minVal, maxVal)
	}
	return nil
}
