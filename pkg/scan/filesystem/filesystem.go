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
	"context"
	"fmt"
	"io"

	"github.com/palantir/log4j-sniffer/pkg/scan"
)

// Crawl crawls identifying and reporting vulnerable files according to crawl.Identify and crawl.DefaultReporter using the
// provided configuration. Returns the number of issues that were found.
func Crawl(ctx context.Context, config scan.Config, stdout, stderr io.Writer) (int64, error) {
	scanner := scan.NewScannerFromConfig(config, stdout, stderr)
	crawlStats, err := scanner.Crawl(ctx, config.Root, scanner.Identify, scanner.Collect)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error crawling: %v", err)
		return 0, err
	}

	count := scanner.Count()
	if config.OutputSummary {
		if err := scan.WriteSummary(stdout, config, crawlStats, count); err != nil {
			return 0, err
		}
	}
	return count, nil
}
