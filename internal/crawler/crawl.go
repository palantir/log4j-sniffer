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
	"context"
	"regexp"
	"time"

	"github.com/palantir/log4j-sniffer/internal/generated/metrics/metrics"
	"github.com/palantir/log4j-sniffer/pkg/archive"
	"github.com/palantir/log4j-sniffer/pkg/crawl"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Crawl crawls identifying and reporting vulnerable files according to crawl.Identify and crawl.Reporter.
// Crawl will emit a status metric each time it is run to signify whether the crawl was successful or not.
// The archiveListTimeout is the per-archive timeout.
func Crawl(ctx context.Context, archiveListTimeout time.Duration, root string, ignores []*regexp.Regexp) error {
	identifier := crawl.NewIdentifier(archiveListTimeout, archive.ReadZipFilePaths, archive.ReadTarGzFilePaths)
	crawler := crawl.Crawler{IgnoreDirs: ignores}
	reporter := crawl.Reporter{}

	if err := crawler.Crawl(ctx, root, identifier.Identify, reporter.Collect); err != nil {
		svc1log.FromContext(ctx).Error("Error crawling",
			svc1log.Stacktrace(err))
		metrics.Crawl(ctx).Status().Gauge().Update(1)
		return err
	}
	metrics.Crawl(ctx).Status().Gauge().Update(0)

	count := reporter.Count()
	if count > 0 {
		svc1log.FromContext(ctx).Info("Files affected by CVE-2021-45046 detected",
			svc1log.SafeParam("vulnerableFileCount", count))
	} else {
		svc1log.FromContext(ctx).Info("No files affected by CVE-2021-45046 detected")
	}
	metrics.Report(ctx).VulnerableFilesFound().Gauge().Update(count)
	return nil
}
