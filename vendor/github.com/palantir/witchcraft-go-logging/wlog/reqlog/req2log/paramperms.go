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

package req2log

import (
	"strings"
)

type ParamPerms interface {
	// Safe returns true if the parameter with the provided name is safe to log. Case-insensitive.
	Safe(paramName string) bool
	// Forbidden returns true if the provided parameter is forbidden from being logged (that is, it should not be logged
	// at all, even as an unsafe parameter). Case-insensitive.
	Forbidden(paramName string) bool
}

type paramPermsImpl struct {
	safe      map[string]struct{}
	forbidden map[string]struct{}
}

func NewParamPerms(safe, forbidden []string) ParamPerms {
	var safeMap map[string]struct{}
	if len(safe) > 0 {
		safeMap = make(map[string]struct{})
		for _, k := range safe {
			safeMap[strings.ToLower(k)] = struct{}{}
		}
	}
	var forbiddenMap map[string]struct{}
	if len(forbidden) > 0 {
		forbiddenMap = make(map[string]struct{})
		for _, k := range forbidden {
			forbiddenMap[strings.ToLower(k)] = struct{}{}
		}
	}
	return &paramPermsImpl{
		safe:      safeMap,
		forbidden: forbiddenMap,
	}
}

func (p *paramPermsImpl) Safe(paramName string) bool {
	_, ok := p.safe[strings.ToLower(paramName)]
	return ok
}

func (p *paramPermsImpl) Forbidden(paramName string) bool {
	_, ok := p.forbidden[strings.ToLower(paramName)]
	return ok
}

type combinedParamPermsImpl []ParamPerms

func CombinedParamPerms(perms ...ParamPerms) ParamPerms {
	return combinedParamPermsImpl(perms)
}

func (c combinedParamPermsImpl) Safe(paramName string) bool {
	if c.Forbidden(paramName) {
		return false
	}
	for _, p := range c {
		if p == nil {
			continue
		}
		if p.Safe(paramName) {
			return true
		}
	}
	return false
}

func (c combinedParamPermsImpl) Forbidden(paramName string) bool {
	for _, p := range c {
		if p == nil {
			continue
		}
		if p.Forbidden(paramName) {
			return true
		}
	}
	return false
}
