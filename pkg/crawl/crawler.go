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

package crawl

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/palantir/log4j-sniffer/internal/generated/metrics/metrics"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Crawler crawls filesystems, matching and conditionally processing files.
type Crawler struct {
	IgnoreDirs []*regexp.Regexp
}

// MatchFunc is used to match a file for processing.
// If returning a positive finding, a file will be passed onto the ProcessFunc.
type MatchFunc func(ctx context.Context, path string, d fs.DirEntry) (Finding, Versions, error)

// ProcessFunc processes the given matched file.
type ProcessFunc func(ctx context.Context, path string, d fs.DirEntry, result Finding, version Versions)

// Crawl crawls the provided root directory. Each file is passed to the provided match function, which returns true if
// the path should be processed by the provided process function. On encountering a directory, the path will be compared
// against all IgnoreDirs configured in the Crawler. If any pattern matches, the directory (and all files nested inside
// the directory) will be ignored.
func (c Crawler) Crawl(ctx context.Context, root string, match MatchFunc, process ProcessFunc) error {
	var filesScanned int64
	var permissionDeniedCount int64
	start := time.Now()
	svc1log.FromContext(ctx).Info("Crawl started")
	defer func() {
		duration := time.Since(start)
		metrics.Crawl(ctx).DurationMilliseconds().Gauge().Update(duration.Milliseconds())
		svc1log.FromContext(ctx).Info("Crawl complete",
			svc1log.SafeParam("crawlDuration", duration.String()),
			svc1log.SafeParam("permissionDeniedCount", permissionDeniedCount),
			svc1log.SafeParam("filesScanned", filesScanned))
	}()
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			switch {
			case os.IsPermission(err):
				permissionDeniedCount++
				return nil
			case os.IsNotExist(err):
				// Root should always exist, to pick up on misconfigured service, but log4j-sniffer can encounter transient
				// files when walking, where WalkDir lists the directory entries but the entry disappears before or
				// during the walk function iterating over it.
				if path == root {
					return err
				}
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			if c.includeDir(path) {
				return nil
			}
			return fs.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		filesScanned++
		matched, version, err := match(ctx, path, d)
		if err != nil {
			svc1log.FromContext(ctx).Warn("Error processing path",
				svc1log.Stacktrace(err),
				svc1log.UnsafeParam("path", path),
				svc1log.UnsafeParam("name", d.Name()))
			return nil
		}
		if matched == NothingDetected {
			return nil
		}
		process(ctx, path, d, matched, version)
		return err
	})
}

func (c Crawler) includeDir(path string) bool {
	for _, pattern := range c.IgnoreDirs {
		if pattern.MatchString(path) {
			return false
		}
	}
	return true
}
