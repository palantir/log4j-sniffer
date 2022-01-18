// Copyright (c) 2022 Palantir Technologies. All rights reserved.
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

package crawl

import (
	"strings"
)

// nestedPaths represents the path taken to get to a given file that is being walked.
// Each element of the slice represents a single walking layer, which could be a file
// or archive.
// For example, ["/path/to/archive", "path/to/nested_archive", "path/to/file"] would
// represent a file being walked that is nested into two layers of archive.
type nestedPaths []string

// Joined provides a string representation of the given nestedPaths, where each layer
// is separated by a '!'.
func (n nestedPaths) Joined() string {
	return strings.Join(n, "!")
}
