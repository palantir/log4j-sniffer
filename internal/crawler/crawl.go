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

package crawler

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/palantir/log4j-sniffer/pkg/archive"
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

// Crawl crawls identifying and reporting vulnerable files according to crawl.Identify and crawl.Reporter using the
// provided configuration. Returns the number of issues that were found.
func Crawl(ctx context.Context, config Config, stdout, stderr io.Writer) (int64, error) {
	identifier := crawl.NewIdentifier(config.ArchiveListTimeout, config.ArchiveMaxDepth, zip.OpenReader, archive.WalkZipFiles, archive.WalkTarGzFiles)
	crawler := crawl.Crawler{
		ErrorWriter: stderr,
		IgnoreDirs:  config.Ignores,
	}
	reporter := crawl.Reporter{
		OutputJSON:      config.OutputJSON,
		OutputWriter:    stdout,
		DisableCVE45105: config.DisableCVE45105,
	}

	crawlStats, err := crawler.Crawl(ctx, config.Root, identifier.Identify, reporter.Collect)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error crawling: %v", err)
		return 0, err
	}

	count := reporter.Count()
	if config.OutputSummary {
		cveInfo := "CVE-2021-45046"
		if !config.DisableCVE45105 {
			cveInfo += " or CVE-2021-45105"
		}

		var output string
		if config.OutputJSON {
			jsonBytes, err := json.Marshal(SummaryJSON{
				Stats:            crawlStats,
				NumImpactedFiles: count,
			})
			if err != nil {
				return 0, err
			}
			output = string(jsonBytes)
		} else {
			if count > 0 {
				output = fmt.Sprintf("Files affected by %s detected: %d file(s) impacted by %s", cveInfo, count, cveInfo)
			} else {
				output = fmt.Sprintf("No files affected by %s detected", cveInfo)
			}
			output += fmt.Sprintf("\n%d total files scanned, skipped %d paths due to permission denied errors, encountered %d errors processing paths", crawlStats.FilesScanned, crawlStats.PermissionDeniedCount, crawlStats.PathErrorCount)
		}
		_, _ = fmt.Fprintln(stdout, output)
	}
	return count, nil
}
