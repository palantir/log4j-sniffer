// Copyright (c) 2021 Palantir Technologies. All rights reserved.
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

package scan

import (
	"regexp"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/crawl"
)

type Config struct {
	// Root is the root directory for the crawl operation
	Root string
	// ArchiveListTimeout is the maximum amount of time that will be spent analyzing an archive. Once this duration has
	// passed for a single archive, it is skipped and recorded as such.
	ArchiveListTimeout time.Duration
	// ArchiveMaxDepth is the maximum archive depth to recurse into. A value of 0 will open up an archive on the
	// filesystem but will not recurse into any nested archives within it.
	ArchiveMaxDepth uint
	// ArchiveMaxDepth is the maximum nested archive size that will be unarchived for inspection.
	ArchiveMaxSize uint
	// If true, disables detection of CVE-45105
	DisableCVE45105 bool
	// Ignores specifies the regular expressions used to determine which directories to omit.
	Ignores []*regexp.Regexp
	// If true, causes all output to be in JSON format (one JSON object per line).
	OutputJSON bool
	// If true, prints summary output after completion.
	OutputSummary bool
}

type SummaryJSON struct {
	crawl.Stats
	NumImpactedFiles int64 `json:"numImpactedFiles"`
}
