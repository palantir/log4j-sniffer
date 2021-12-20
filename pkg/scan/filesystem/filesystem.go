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

package filesystem

import (
	"archive/zip"
	"context"
	"fmt"
	"io"

	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/log4j-sniffer/pkg/scan"
)

// Crawl crawls identifying and reporting vulnerable files according to crawl.Identify and crawl.DefaultReporter using the
// provided configuration. Returns the number of issues that were found.
func Crawl(ctx context.Context, config scan.Config, stdout, stderr io.Writer) (int64, error) {
	identifier := crawl.Log4jIdentifier{
		ZipWalker:          archive.WalkZipFiles,
		TgzZWalker:         archive.WalkTarGzFiles,
		ArchiveWalkTimeout: config.ArchiveListTimeout,
		OpenFileZipReader:  zip.OpenReader,
		ArchiveMaxDepth:    config.ArchiveMaxDepth,
		ArchiveMaxSize:     config.ArchiveMaxSize,
	}
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
		if err := scan.WriteSummary(stdout, config, crawlStats, count); err != nil {
			return 0, err
		}
	}
	return count, nil
}
