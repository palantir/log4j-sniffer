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

package gopath

import (
	"strings"
)

// TrimPrefix trims everything up to the first /src/ as a heuristic for limiting the file to the go import path. This is a
// very simple heuristic that will break if the GOPATH exists in a directory with /src/ in the path
// (e.g. ~/src/go/src/github...), but is considered best-effort.
func TrimPrefix(absolutePath string) string {
	const srcDir = `/src/`
	if idx := strings.Index(absolutePath, srcDir); idx >= 0 {
		return absolutePath[idx+len(srcDir):]
	}
	return absolutePath
}
