// Copyright (c) 2018 Palantir Technologies. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uuid

import (
	"encoding"
	"fmt"

	"github.com/palantir/pkg/uuid/internal/uuid"
)

func NewUUID() UUID {
	return [16]byte(uuid.New())
}

var (
	_ fmt.Stringer             = UUID{}
	_ encoding.TextMarshaler   = UUID{}
	_ encoding.TextUnmarshaler = &UUID{}
)

// UUID (universally unique identifier) is a 128-bit number used to
// identify information in computer systems as defined in RFC 4122.
type UUID [16]byte

func ParseUUID(s string) (UUID, error) {
	var u UUID
	err := (&u).UnmarshalText([]byte(s))
	return u, err
}

// String returns uuid string representation "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
// or "" if uuid is invalid.
func (u UUID) String() string {
	return uuid.UUID(u).String()
}

// MarshalText implements encoding.TextMarshaler.
func (u UUID) MarshalText() ([]byte, error) {
	return uuid.UUID(u).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (u *UUID) UnmarshalText(data []byte) error {
	return (*uuid.UUID)(u).UnmarshalText(data)
}
